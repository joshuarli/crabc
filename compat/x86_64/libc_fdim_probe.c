/*
 * Static Linux/x86-64 positive-difference C ABI regression.
 *
 * This fixture deliberately selects only binary64 `fdim` and binary32
 * `fdimf`. It runs unchanged against pinned musl 1.2.6 and a freestanding
 * crabc archive. Function pointers prevent compiler builtins from replacing
 * either C ABI call. The checks pin musl's left-to-right quiet-NaN choice,
 * positive-zero result for a non-positive difference, the current MXCSR
 * rounding direction for an inexact positive difference, and arithmetic
 * overflow flags. It is not an `exp10`/`pow10`, integer-rounding, binary80,
 * special-function, or general libm claim.
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

typedef double (*double_binary_function)(double, double);
typedef float (*float_binary_function)(float, float);

/* Parentheses force the callable ABI symbols rather than compiler builtins. */
static double_binary_function volatile direct_fdim = (fdim);
static float_binary_function volatile direct_fdimf = (fdimf);

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

static double double_from_bits(uint64_t bits)
{
	union {
		double value;
		uint64_t bits;
	} view = { .bits = bits };
	return view.value;
}

static float float_from_bits(uint32_t bits)
{
	union {
		float value;
		uint32_t bits;
	} view = { .bits = bits };
	return view.value;
}

static int check_binary64_values(void)
{
	volatile double negative_zero = -0.0;
	volatile double quiet_nan_x = double_from_bits(UINT64_C(0x7ff8000000000041));
	volatile double quiet_nan_y = double_from_bits(UINT64_C(0x7ff8000000000042));
	volatile double signaling_nan_x = double_from_bits(UINT64_C(0x7ff0000000000041));
	volatile double signaling_nan_y = double_from_bits(UINT64_C(0x7ff0000000000042));

	if (double_bits(direct_fdim(3.5, 1.25)) != UINT64_C(0x4002000000000000))
		return 1;
	if (double_bits(direct_fdim(negative_zero, 0.0)) != 0 ||
		double_bits(direct_fdim(-1.0, -2.0)) != UINT64_C(0x3ff0000000000000))
		return 2;
	if (double_bits(direct_fdim(HUGE_VAL, HUGE_VAL)) != 0 ||
		double_bits(direct_fdim(-HUGE_VAL, 1.0)) != 0 ||
		double_bits(direct_fdim(HUGE_VAL, 1.0)) != UINT64_C(0x7ff0000000000000))
		return 3;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 4;
	if (double_bits(direct_fdim(quiet_nan_x, 1.0)) != UINT64_C(0x7ff8000000000041) ||
		double_bits(direct_fdim(1.0, quiet_nan_y)) != UINT64_C(0x7ff8000000000042) ||
		double_bits(direct_fdim(quiet_nan_x, quiet_nan_y)) != UINT64_C(0x7ff8000000000041) ||
		double_bits(direct_fdim(quiet_nan_x, signaling_nan_y)) != UINT64_C(0x7ff8000000000041) ||
		fetestexcept(FE_INVALID) != 0 ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 5;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 6;
	if (double_bits(direct_fdim(signaling_nan_x, 1.0)) != UINT64_C(0x7ff0000000000041) ||
		double_bits(direct_fdim(1.0, signaling_nan_y)) != UINT64_C(0x7ff0000000000042) ||
		double_bits(direct_fdim(signaling_nan_x, signaling_nan_y)) != UINT64_C(0x7ff0000000000041) ||
		fetestexcept(FE_INVALID) != 0 ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 7;
	return 0;
}

static int check_binary32_values(void)
{
	volatile float negative_zero = -0.0f;
	volatile float quiet_nan_x = float_from_bits(UINT32_C(0x7fc00041));
	volatile float quiet_nan_y = float_from_bits(UINT32_C(0x7fc00042));
	volatile float signaling_nan_x = float_from_bits(UINT32_C(0x7f800041));
	volatile float signaling_nan_y = float_from_bits(UINT32_C(0x7f800042));

	if (float_bits(direct_fdimf(3.5f, 1.25f)) != UINT32_C(0x40100000))
		return 1;
	if (float_bits(direct_fdimf(negative_zero, 0.0f)) != 0 ||
		float_bits(direct_fdimf(-1.0f, -2.0f)) != UINT32_C(0x3f800000))
		return 2;
	if (float_bits(direct_fdimf(HUGE_VALF, HUGE_VALF)) != 0 ||
		float_bits(direct_fdimf(-HUGE_VALF, 1.0f)) != 0 ||
		float_bits(direct_fdimf(HUGE_VALF, 1.0f)) != UINT32_C(0x7f800000))
		return 3;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 4;
	if (float_bits(direct_fdimf(quiet_nan_x, 1.0f)) != UINT32_C(0x7fc00041) ||
		float_bits(direct_fdimf(1.0f, quiet_nan_y)) != UINT32_C(0x7fc00042) ||
		float_bits(direct_fdimf(quiet_nan_x, quiet_nan_y)) != UINT32_C(0x7fc00041) ||
		float_bits(direct_fdimf(quiet_nan_x, signaling_nan_y)) != UINT32_C(0x7fc00041) ||
		fetestexcept(FE_INVALID) != 0 ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 5;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 6;
	if (float_bits(direct_fdimf(signaling_nan_x, 1.0f)) != UINT32_C(0x7f800041) ||
		float_bits(direct_fdimf(1.0f, signaling_nan_y)) != UINT32_C(0x7f800042) ||
		float_bits(direct_fdimf(signaling_nan_x, signaling_nan_y)) != UINT32_C(0x7f800041) ||
		fetestexcept(FE_INVALID) != 0 ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 7;
	return 0;
}

static int check_binary64_rounding(void)
{
	static const int modes[4] = {
		FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
	};
	static const uint64_t expected[4] = {
		UINT64_C(0x3ff0000000000000), UINT64_C(0x3fefffffffffffff),
		UINT64_C(0x3ff0000000000000), UINT64_C(0x3fefffffffffffff),
	};
	int index;

	for (index = 0; index < 4; index++) {
		volatile double x = 1.0;
		volatile double y = 0x1p-54;
		if (fesetround(modes[index]) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
			return 1 + index;
		if (double_bits(direct_fdim(x, y)) != expected[index])
			return 5 + index;
		if (fetestexcept(FE_ALL_EXCEPT) != FE_INEXACT)
			return 9 + index;
	}
	return 0;
}

static int check_binary32_rounding(void)
{
	static const int modes[4] = {
		FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
	};
	static const uint32_t expected[4] = {
		UINT32_C(0x3f800000), UINT32_C(0x3f7fffff),
		UINT32_C(0x3f800000), UINT32_C(0x3f7fffff),
	};
	int index;

	for (index = 0; index < 4; index++) {
		volatile float x = 1.0f;
		volatile float y = 0x1p-25f;
		if (fesetround(modes[index]) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
			return 1 + index;
		if (float_bits(direct_fdimf(x, y)) != expected[index])
			return 5 + index;
		if (fetestexcept(FE_ALL_EXCEPT) != FE_INEXACT)
			return 9 + index;
	}
	return 0;
}

static int check_overflow(void)
{
	volatile double max = DBL_MAX;
	volatile float maxf = FLT_MAX;

	if (fesetround(FE_TONEAREST) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	if (double_bits(direct_fdim(max, -max)) != UINT64_C(0x7ff0000000000000) ||
		(fetestexcept(FE_OVERFLOW | FE_INEXACT) & (FE_OVERFLOW | FE_INEXACT)) !=
			(FE_OVERFLOW | FE_INEXACT))
		return 2;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 3;
	if (float_bits(direct_fdimf(maxf, -maxf)) != UINT32_C(0x7f800000) ||
		(fetestexcept(FE_OVERFLOW | FE_INEXACT) & (FE_OVERFLOW | FE_INEXACT)) !=
			(FE_OVERFLOW | FE_INEXACT))
		return 4;
	return 0;
}

int crabc_x86_64_fdim_probe(void)
{
	fenv_t original;
	int status;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	status = check_binary64_values();
	if (status == 0)
		status = check_binary32_values() == 0 ? 0 : 20;
	if (status == 0)
		status = check_binary64_rounding() == 0 ? 0 : 30;
	if (status == 0)
		status = check_binary32_rounding() == 0 ? 0 : 40;
	if (status == 0)
		status = check_overflow() == 0 ? 0 : 50;
	if (fesetenv(&original) != 0 && status == 0)
		status = 60;
	return status;
}

#ifndef CRABC_FDIM_FREESTANDING
int main(void)
{
	return crabc_x86_64_fdim_probe();
}
#endif
