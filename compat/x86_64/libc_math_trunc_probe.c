/*
 * Static Linux/x86-64 trunc/truncf C ABI regression.
 *
 * This fixture selects only binary64/binary32 `trunc*`. It runs unchanged
 * against pinned musl 1.2.6 and a freestanding crabc archive. Function
 * pointers prevent compiler builtins from replacing the C ABI calls. The
 * checks pin raw NaN/signed-zero handling plus musl's narrow FE_INEXACT
 * force-evaluation rule; this is not a long-double, fenv-rounding, special,
 * complex, or general libm claim.
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

/* Parentheses force callable C ABI symbols rather than compiler builtins. */
static double_unary_function volatile direct_trunc = (trunc);
static float_unary_function volatile direct_truncf = (truncf);

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

	if (double_bits(direct_trunc(-3.75)) != UINT64_C(0xc008000000000000) ||
		double_bits(direct_trunc(3.75)) != UINT64_C(0x4008000000000000) ||
		double_bits(direct_trunc(negative_zero)) != UINT64_C(0x8000000000000000) ||
		double_bits(direct_trunc(-HUGE_VAL)) != UINT64_C(0xfff0000000000000))
		return 1;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 2;
	if (double_bits(direct_trunc(quiet_nan)) != UINT64_C(0xfff8000000000041) ||
		double_bits(direct_trunc(signaling_nan)) != UINT64_C(0xfff0000000000042) ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 3;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 4;
	if (double_bits(direct_trunc(-0.75)) != UINT64_C(0x8000000000000000) ||
		fetestexcept(FE_ALL_EXCEPT) != FE_INEXACT)
		return 5;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 6;
	if (double_bits(direct_trunc(double_from_bits(UINT64_C(0x0000000000000001)))) != 0 ||
		fetestexcept(FE_INEXACT) == 0 || fetestexcept(FE_INVALID) != 0)
		return 7;
	return 0;
}

static int check_binary32_values(void)
{
	volatile float negative_zero = -0.0f;
	volatile float quiet_nan = float_from_bits(UINT32_C(0xffc00041));
	volatile float signaling_nan = float_from_bits(UINT32_C(0xff800042));

	if (float_bits(direct_truncf(-3.75f)) != UINT32_C(0xc0400000) ||
		float_bits(direct_truncf(3.75f)) != UINT32_C(0x40400000) ||
		float_bits(direct_truncf(negative_zero)) != UINT32_C(0x80000000) ||
		float_bits(direct_truncf(-HUGE_VALF)) != UINT32_C(0xff800000))
		return 1;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 2;
	if (float_bits(direct_truncf(quiet_nan)) != UINT32_C(0xffc00041) ||
		float_bits(direct_truncf(signaling_nan)) != UINT32_C(0xff800042) ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 3;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 4;
	if (float_bits(direct_truncf(-0.75f)) != UINT32_C(0x80000000) ||
		fetestexcept(FE_ALL_EXCEPT) != FE_INEXACT)
		return 5;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 6;
	if (float_bits(direct_truncf(float_from_bits(UINT32_C(0x00000001)))) != 0 ||
		fetestexcept(FE_INEXACT) == 0 || fetestexcept(FE_INVALID) != 0)
		return 7;
	return 0;
}

static int check_fenv_boundary(void)
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
		if (double_bits(direct_trunc(-0.75)) != UINT64_C(0x8000000000000000) ||
			float_bits(direct_truncf(0.75f)) != 0)
			return 9 + index;
		if (fegetround() != modes[index] ||
			fetestexcept(FE_INVALID) != 0 ||
			fetestexcept(FE_ALL_EXCEPT) != (FE_DIVBYZERO | FE_INEXACT))
			return 13 + index;
	}
	return 0;
}

int crabc_x86_64_math_trunc_probe(void)
{
	fenv_t original;
	int status;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	status = check_binary64_values();
	if (status == 0)
		status = check_binary32_values() == 0 ? 0 : 20;
	if (status == 0)
		status = check_fenv_boundary() == 0 ? 0 : 40;
	if (fesetenv(&original) != 0 && status == 0)
		status = 60;
	return status;
}

#ifndef CRABC_MATH_TRUNC_FREESTANDING
int main(void)
{
	return crabc_x86_64_math_trunc_probe();
}
#endif
