/*
 * Static Linux/x86-64 bit-sign math C ABI regression.
 *
 * This fixture selects only binary64/binary32 `fabs*` and `copysign*`. It
 * runs unchanged against pinned musl 1.2.6 and a freestanding crabc archive.
 * Function pointers prevent compiler builtins from replacing the C ABI calls.
 * The checks pin raw NaN payload/sign handling and the non-signaling,
 * fenv-preserving bit-manipulation path; this is not a long-double, fdim,
 * rounding, special-function, or general libm claim.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stdint.h>

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);
typedef double (*double_binary_function)(double, double);
typedef float (*float_binary_function)(float, float);

/* Parentheses force callable C ABI symbols rather than compiler builtins. */
static double_unary_function volatile direct_fabs = (fabs);
static float_unary_function volatile direct_fabsf = (fabsf);
static double_binary_function volatile direct_copysign = (copysign);
static float_binary_function volatile direct_copysignf = (copysignf);

static uint64_t double_bits(double value)
{
	union { double value; uint64_t bits; } view = { .value = value };
	return view.bits;
}

static uint32_t float_bits(float value)
{
	union { float value; uint32_t bits; } view = { .value = value };
	return view.bits;
}

static double double_from_bits(uint64_t bits)
{
	union { double value; uint64_t bits; } view = { .bits = bits };
	return view.value;
}

static float float_from_bits(uint32_t bits)
{
	union { float value; uint32_t bits; } view = { .bits = bits };
	return view.value;
}

static int check_binary64_values(void)
{
	volatile double negative_zero = -0.0;
	volatile double quiet_nan = double_from_bits(UINT64_C(0xfff8000000000041));
	volatile double signaling_nan = double_from_bits(UINT64_C(0xfff0000000000042));
	volatile double sign_nan = double_from_bits(UINT64_C(0xfff8000000000053));

	if (double_bits(direct_fabs(-3.5)) != UINT64_C(0x400c000000000000) ||
		double_bits(direct_fabs(negative_zero)) != 0 ||
		double_bits(direct_fabs(-HUGE_VAL)) != UINT64_C(0x7ff0000000000000))
		return 1;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 2;
	if (double_bits(direct_fabs(quiet_nan)) != UINT64_C(0x7ff8000000000041) ||
		double_bits(direct_fabs(signaling_nan)) != UINT64_C(0x7ff0000000000042) ||
		fetestexcept(FE_INVALID) != 0 ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 3;
	if (double_bits(direct_copysign(-3.5, 0.0)) != UINT64_C(0x400c000000000000) ||
		double_bits(direct_copysign(3.5, negative_zero)) != UINT64_C(0xc00c000000000000) ||
		double_bits(direct_copysign(quiet_nan, 1.0)) != UINT64_C(0x7ff8000000000041) ||
		double_bits(direct_copysign(signaling_nan, negative_zero)) != UINT64_C(0xfff0000000000042) ||
		double_bits(direct_copysign(1.0, sign_nan)) != UINT64_C(0xbff0000000000000) ||
		fetestexcept(FE_INVALID) != 0 ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 4;
	return 0;
}

static int check_binary32_values(void)
{
	volatile float negative_zero = -0.0f;
	volatile float quiet_nan = float_from_bits(UINT32_C(0xffc00041));
	volatile float signaling_nan = float_from_bits(UINT32_C(0xff800042));
	volatile float sign_nan = float_from_bits(UINT32_C(0xffc00053));

	if (float_bits(direct_fabsf(-3.5f)) != UINT32_C(0x40600000) ||
		float_bits(direct_fabsf(negative_zero)) != 0 ||
		float_bits(direct_fabsf(-HUGE_VALF)) != UINT32_C(0x7f800000))
		return 1;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 2;
	if (float_bits(direct_fabsf(quiet_nan)) != UINT32_C(0x7fc00041) ||
		float_bits(direct_fabsf(signaling_nan)) != UINT32_C(0x7f800042) ||
		fetestexcept(FE_INVALID) != 0 ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 3;
	if (float_bits(direct_copysignf(-3.5f, 0.0f)) != UINT32_C(0x40600000) ||
		float_bits(direct_copysignf(3.5f, negative_zero)) != UINT32_C(0xc0600000) ||
		float_bits(direct_copysignf(quiet_nan, 1.0f)) != UINT32_C(0x7fc00041) ||
		float_bits(direct_copysignf(signaling_nan, negative_zero)) != UINT32_C(0xff800042) ||
		float_bits(direct_copysignf(1.0f, sign_nan)) != UINT32_C(0xbf800000) ||
		fetestexcept(FE_INVALID) != 0 ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 4;
	return 0;
}

static int check_fenv_preservation(void)
{
	static const int modes[4] = {
		FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
	};
	volatile double signaling_nan = double_from_bits(UINT64_C(0x7ff0000000000061));
	volatile float signaling_nanf = float_from_bits(UINT32_C(0x7f800061));
	int index;

	for (index = 0; index < 4; index++) {
		if (fesetround(modes[index]) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
			return 1 + index;
		if (feraiseexcept(FE_DIVBYZERO) != 0)
			return 5 + index;
		if (double_bits(direct_fabs(signaling_nan)) != UINT64_C(0x7ff0000000000061) ||
			float_bits(direct_fabsf(signaling_nanf)) != UINT32_C(0x7f800061) ||
			double_bits(direct_copysign(signaling_nan, -0.0)) != UINT64_C(0xfff0000000000061) ||
			float_bits(direct_copysignf(signaling_nanf, -0.0f)) != UINT32_C(0xff800061))
			return 9 + index;
		if (fegetround() != modes[index] ||
			fetestexcept(FE_INVALID) != 0 ||
			fetestexcept(FE_ALL_EXCEPT) != FE_DIVBYZERO)
			return 13 + index;
	}
	return 0;
}

int crabc_x86_64_math_bit_sign_probe(void)
{
	fenv_t original;
	int status;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	status = check_binary64_values();
	if (status == 0)
		status = check_binary32_values() == 0 ? 0 : 20;
	if (status == 0)
		status = check_fenv_preservation() == 0 ? 0 : 40;
	if (fesetenv(&original) != 0 && status == 0)
		status = 60;
	return status;
}

#ifndef CRABC_MATH_BIT_SIGN_FREESTANDING
int main(void)
{
	return crabc_x86_64_math_bit_sign_probe();
}
#endif
