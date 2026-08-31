/*
 * Static Linux/x86-64 fmax/fmin C ABI regression.
 *
 * This fixture selects only binary64/binary32 `fmax*` and `fmin*`. It runs
 * unchanged against pinned musl 1.2.6 and a freestanding crabc archive.
 * Function pointers prevent compiler builtins from replacing the C ABI calls.
 * The checks pin musl's non-signaling operand selection for quiet/signaling
 * NaNs, Annex F signed-zero rule, and fenv-preserving comparison path; this is
 * not a long-double, fdim, rounding, special-function, or general libm claim.
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

/* Parentheses force callable C ABI symbols rather than compiler builtins. */
static double_binary_function volatile direct_fmax = (fmax);
static float_binary_function volatile direct_fmaxf = (fmaxf);
static double_binary_function volatile direct_fmin = (fmin);
static float_binary_function volatile direct_fminf = (fminf);

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
	volatile double quiet_nan_x = double_from_bits(UINT64_C(0xfff8000000000041));
	volatile double quiet_nan_y = double_from_bits(UINT64_C(0x7ff8000000000042));
	volatile double signaling_nan_x = double_from_bits(UINT64_C(0xfff0000000000043));
	volatile double signaling_nan_y = double_from_bits(UINT64_C(0x7ff0000000000044));

	if (double_bits(direct_fmax(-3.5, 1.25)) != UINT64_C(0x3ff4000000000000) ||
		double_bits(direct_fmin(-3.5, 1.25)) != UINT64_C(0xc00c000000000000) ||
		double_bits(direct_fmax(-HUGE_VAL, HUGE_VAL)) != UINT64_C(0x7ff0000000000000) ||
		double_bits(direct_fmin(-HUGE_VAL, HUGE_VAL)) != UINT64_C(0xfff0000000000000))
		return 1;
	if (double_bits(direct_fmax(negative_zero, 0.0)) != 0 ||
		double_bits(direct_fmax(0.0, negative_zero)) != 0 ||
		double_bits(direct_fmin(negative_zero, 0.0)) != UINT64_C(0x8000000000000000) ||
		double_bits(direct_fmin(0.0, negative_zero)) != UINT64_C(0x8000000000000000))
		return 2;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 3;
	if (double_bits(direct_fmax(quiet_nan_x, 1.0)) != UINT64_C(0x3ff0000000000000) ||
		double_bits(direct_fmax(1.0, quiet_nan_y)) != UINT64_C(0x3ff0000000000000) ||
		double_bits(direct_fmax(quiet_nan_x, quiet_nan_y)) != UINT64_C(0x7ff8000000000042) ||
		double_bits(direct_fmin(quiet_nan_x, 1.0)) != UINT64_C(0x3ff0000000000000) ||
		double_bits(direct_fmin(1.0, quiet_nan_y)) != UINT64_C(0x3ff0000000000000) ||
		double_bits(direct_fmin(quiet_nan_x, quiet_nan_y)) != UINT64_C(0x7ff8000000000042) ||
		fetestexcept(FE_INVALID) != 0 || fetestexcept(FE_ALL_EXCEPT) != 0)
		return 4;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 5;
	if (double_bits(direct_fmax(signaling_nan_x, 1.0)) != UINT64_C(0x3ff0000000000000) ||
		double_bits(direct_fmax(1.0, signaling_nan_y)) != UINT64_C(0x3ff0000000000000) ||
		double_bits(direct_fmax(signaling_nan_x, signaling_nan_y)) != UINT64_C(0x7ff0000000000044) ||
		double_bits(direct_fmin(signaling_nan_x, 1.0)) != UINT64_C(0x3ff0000000000000) ||
		double_bits(direct_fmin(1.0, signaling_nan_y)) != UINT64_C(0x3ff0000000000000) ||
		double_bits(direct_fmin(signaling_nan_x, signaling_nan_y)) != UINT64_C(0x7ff0000000000044) ||
		fetestexcept(FE_INVALID) != 0 || fetestexcept(FE_ALL_EXCEPT) != 0)
		return 6;
	return 0;
}

static int check_binary32_values(void)
{
	volatile float negative_zero = -0.0f;
	volatile float quiet_nan_x = float_from_bits(UINT32_C(0xffc00041));
	volatile float quiet_nan_y = float_from_bits(UINT32_C(0x7fc00042));
	volatile float signaling_nan_x = float_from_bits(UINT32_C(0xff800043));
	volatile float signaling_nan_y = float_from_bits(UINT32_C(0x7f800044));

	if (float_bits(direct_fmaxf(-3.5f, 1.25f)) != UINT32_C(0x3fa00000) ||
		float_bits(direct_fminf(-3.5f, 1.25f)) != UINT32_C(0xc0600000) ||
		float_bits(direct_fmaxf(-HUGE_VALF, HUGE_VALF)) != UINT32_C(0x7f800000) ||
		float_bits(direct_fminf(-HUGE_VALF, HUGE_VALF)) != UINT32_C(0xff800000))
		return 1;
	if (float_bits(direct_fmaxf(negative_zero, 0.0f)) != 0 ||
		float_bits(direct_fmaxf(0.0f, negative_zero)) != 0 ||
		float_bits(direct_fminf(negative_zero, 0.0f)) != UINT32_C(0x80000000) ||
		float_bits(direct_fminf(0.0f, negative_zero)) != UINT32_C(0x80000000))
		return 2;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 3;
	if (float_bits(direct_fmaxf(quiet_nan_x, 1.0f)) != UINT32_C(0x3f800000) ||
		float_bits(direct_fmaxf(1.0f, quiet_nan_y)) != UINT32_C(0x3f800000) ||
		float_bits(direct_fmaxf(quiet_nan_x, quiet_nan_y)) != UINT32_C(0x7fc00042) ||
		float_bits(direct_fminf(quiet_nan_x, 1.0f)) != UINT32_C(0x3f800000) ||
		float_bits(direct_fminf(1.0f, quiet_nan_y)) != UINT32_C(0x3f800000) ||
		float_bits(direct_fminf(quiet_nan_x, quiet_nan_y)) != UINT32_C(0x7fc00042) ||
		fetestexcept(FE_INVALID) != 0 || fetestexcept(FE_ALL_EXCEPT) != 0)
		return 4;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 5;
	if (float_bits(direct_fmaxf(signaling_nan_x, 1.0f)) != UINT32_C(0x3f800000) ||
		float_bits(direct_fmaxf(1.0f, signaling_nan_y)) != UINT32_C(0x3f800000) ||
		float_bits(direct_fmaxf(signaling_nan_x, signaling_nan_y)) != UINT32_C(0x7f800044) ||
		float_bits(direct_fminf(signaling_nan_x, 1.0f)) != UINT32_C(0x3f800000) ||
		float_bits(direct_fminf(1.0f, signaling_nan_y)) != UINT32_C(0x3f800000) ||
		float_bits(direct_fminf(signaling_nan_x, signaling_nan_y)) != UINT32_C(0x7f800044) ||
		fetestexcept(FE_INVALID) != 0 || fetestexcept(FE_ALL_EXCEPT) != 0)
		return 6;
	return 0;
}

static int check_fenv_preservation(void)
{
	static const int modes[4] = {
		FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
	};
	int index;

	for (index = 0; index < 4; index++) {
		if (fesetround(modes[index]) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
			return 1 + index;
		if (feraiseexcept(FE_DIVBYZERO) != 0)
			return 5 + index;
		if (double_bits(direct_fmax(-0.0, 0.0)) != 0 ||
			double_bits(direct_fmin(-0.0, 0.0)) != UINT64_C(0x8000000000000000) ||
			float_bits(direct_fmaxf(-0.0f, 0.0f)) != 0 ||
			float_bits(direct_fminf(-0.0f, 0.0f)) != UINT32_C(0x80000000))
			return 9 + index;
		if (fegetround() != modes[index] || fetestexcept(FE_INVALID) != 0 ||
			fetestexcept(FE_ALL_EXCEPT) != FE_DIVBYZERO)
			return 13 + index;
	}
	return 0;
}

int crabc_x86_64_math_minmax_probe(void)
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

#ifndef CRABC_MATH_MINMAX_FREESTANDING
int main(void)
{
	return crabc_x86_64_math_minmax_probe();
}
#endif
