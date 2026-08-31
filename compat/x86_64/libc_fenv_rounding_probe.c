/*
 * Static Linux/x86-64 fenv-sensitive rounding ABI probe.
 *
 * This fixture selects exactly rint/nearbyint in binary32, binary64, and x87
 * binary80 form.  Each name is called through a function pointer after the
 * same project-header body passes against pinned musl 1.2.6.  rint must obey
 * the relevant MXCSR/x87 rounding field and raise FE_INEXACT for fractional
 * inputs; nearbyint must return the same value without clearing a preexisting
 * FE_INEXACT flag.  This is not an exp10/pow10/fdim, integer-conversion,
 * general elementary-math, or complete math.elementary-fenv-sensitive claim.
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

typedef double (*double_round_function)(double);
typedef float (*float_round_function)(float);
typedef long double (*long_round_function)(long double);

/* Parentheses force the callable ABI symbols rather than compiler builtins. */
static double_round_function const direct_rint = (rint);
static float_round_function const direct_rintf = (rintf);
static long_round_function const direct_rintl = (rintl);
static double_round_function const direct_nearbyint = (nearbyint);
static float_round_function const direct_nearbyintf = (nearbyintf);
static long_round_function const direct_nearbyintl = (nearbyintl);

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

static uint16_t long_sign_exponent(long double value)
{
	union {
		long double value;
		unsigned char raw[16];
	} view = { .value = value };
	return (uint16_t)view.raw[8] | ((uint16_t)view.raw[9] << 8);
}

static int check_long_value(long double value, int expected)
{
	if (expected == 0)
		return value == 0.0L && long_sign_exponent(value) == 0;
	if (expected == -0x10)
		return value == 0.0L && long_sign_exponent(value) == UINT16_C(0x8000);
	return value == (long double)expected;
}

static uint64_t expected_double_bits(int mode_index, int input_index)
{
	static const uint64_t values[4][4] = {
		{ UINT64_C(0), UINT64_C(0x4000000000000000),
		  UINT64_C(0x8000000000000000), UINT64_C(0xc000000000000000) },
		{ UINT64_C(0), UINT64_C(0x3ff0000000000000),
		  UINT64_C(0xbff0000000000000), UINT64_C(0xc000000000000000) },
		{ UINT64_C(0x3ff0000000000000), UINT64_C(0x4000000000000000),
		  UINT64_C(0x8000000000000000), UINT64_C(0xbff0000000000000) },
		{ UINT64_C(0), UINT64_C(0x3ff0000000000000),
		  UINT64_C(0x8000000000000000), UINT64_C(0xbff0000000000000) },
	};
	return values[mode_index][input_index];
}

static uint32_t expected_float_bits(int mode_index, int input_index)
{
	static const uint32_t values[4][4] = {
		{ UINT32_C(0), UINT32_C(0x40000000),
		  UINT32_C(0x80000000), UINT32_C(0xc0000000) },
		{ UINT32_C(0), UINT32_C(0x3f800000),
		  UINT32_C(0xbf800000), UINT32_C(0xc0000000) },
		{ UINT32_C(0x3f800000), UINT32_C(0x40000000),
		  UINT32_C(0x80000000), UINT32_C(0xbf800000) },
		{ UINT32_C(0), UINT32_C(0x3f800000),
		  UINT32_C(0x80000000), UINT32_C(0xbf800000) },
	};
	return values[mode_index][input_index];
}

static int expected_long_value(int mode_index, int input_index)
{
	static const int values[4][4] = {
		{ 0, 2, -0x10, -2 },
		{ 0, 1, -1, -2 },
		{ 1, 2, -0x10, -1 },
		{ 0, 1, -0x10, -1 },
	};
	return values[mode_index][input_index];
}

static int check_binary64_mode(int mode, int mode_index)
{
	volatile double inputs[4] = { 0.5, 1.5, -0.5, -1.5 };
	int index;

	if (fesetround(mode) != 0)
		return 1;
	for (index = 0; index < 4; index++) {
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 2;
		if (double_bits(direct_rint(inputs[index])) !=
			expected_double_bits(mode_index, index))
			return 3 + index;
		if (!(fetestexcept(FE_INEXACT) & FE_INEXACT))
			return 7 + index;
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 11;
		if (double_bits(direct_nearbyint(inputs[index])) !=
			expected_double_bits(mode_index, index))
			return 12 + index;
		if (fetestexcept(FE_ALL_EXCEPT) != 0)
			return 16 + index;
	}
	return 0;
}

static int check_binary32_mode(int mode, int mode_index)
{
	volatile float inputs[4] = { 0.5f, 1.5f, -0.5f, -1.5f };
	int index;

	if (fesetround(mode) != 0)
		return 1;
	for (index = 0; index < 4; index++) {
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 2;
		if (float_bits(direct_rintf(inputs[index])) !=
			expected_float_bits(mode_index, index))
			return 3 + index;
		if (!(fetestexcept(FE_INEXACT) & FE_INEXACT))
			return 7 + index;
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 11;
		if (float_bits(direct_nearbyintf(inputs[index])) !=
			expected_float_bits(mode_index, index))
			return 12 + index;
		if (fetestexcept(FE_ALL_EXCEPT) != 0)
			return 16 + index;
	}
	return 0;
}

static int check_binary80_mode(int mode, int mode_index)
{
	volatile long double inputs[4] = { 0.5L, 1.5L, -0.5L, -1.5L };
	int index;

	if (fesetround(mode) != 0)
		return 1;
	for (index = 0; index < 4; index++) {
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 2;
		if (!check_long_value(direct_rintl(inputs[index]),
			expected_long_value(mode_index, index)))
			return 3 + index;
		if (!(fetestexcept(FE_INEXACT) & FE_INEXACT))
			return 7 + index;
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 11;
		if (!check_long_value(direct_nearbyintl(inputs[index]),
			expected_long_value(mode_index, index)))
			return 12 + index;
		if (fetestexcept(FE_ALL_EXCEPT) != 0)
			return 16 + index;
	}
	return 0;
}

static int check_preserved_exceptions(void)
{
	volatile double d = 1.5;
	volatile float f = 1.5f;
	volatile long double l = 1.5L;

	if (fesetround(FE_TONEAREST) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	if (feraiseexcept(FE_INEXACT | FE_DIVBYZERO) != 0)
		return 2;
	(void)direct_nearbyint(d);
	(void)direct_nearbyintf(f);
	(void)direct_nearbyintl(l);
	if ((fetestexcept(FE_INEXACT | FE_DIVBYZERO) &
		(FE_INEXACT | FE_DIVBYZERO)) != (FE_INEXACT | FE_DIVBYZERO))
		return 3;
	return 0;
}

static int check_special_values(void)
{
	volatile double negative_zero = -0.0;
	volatile float negative_zerof = -0.0f;
	volatile long double negative_zerol = -0.0L;

	if (double_bits(direct_rint(negative_zero)) != UINT64_C(0x8000000000000000) ||
		double_bits(direct_nearbyint(HUGE_VAL)) != UINT64_C(0x7ff0000000000000) ||
		!isnan(direct_rint(NAN)))
		return 1;
	if (float_bits(direct_rintf(negative_zerof)) != UINT32_C(0x80000000) ||
		float_bits(direct_nearbyintf(HUGE_VALF)) != UINT32_C(0x7f800000) ||
		!isnan(direct_rintf(NAN)))
		return 2;
	if (!check_long_value(direct_rintl(negative_zerol), -0x10) ||
		direct_nearbyintl(HUGE_VALL) != HUGE_VALL ||
		!isnan(direct_rintl((long double)NAN)))
		return 3;
	return 0;
}

int crabc_x86_64_fenv_rounding_probe(void)
{
	static const int modes[4] = {
		FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
	};
	fenv_t original;
	int mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < 4 && status == 0; mode_index++) {
		status = check_binary64_mode(modes[mode_index], mode_index);
		if (status != 0)
			status += 10 + mode_index * 20;
		else {
			status = check_binary32_mode(modes[mode_index], mode_index);
			if (status != 0)
				status += 100 + mode_index * 20;
		}
		if (status == 0) {
			status = check_binary80_mode(modes[mode_index], mode_index);
			if (status != 0)
				status += 190 + mode_index * 20;
		}
	}
	if (status == 0)
		status = check_preserved_exceptions() == 0 ? 0 : 2;
	if (status == 0)
		status = check_special_values() == 0 ? 0 : 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_FENV_ROUNDING_FREESTANDING
int main(void)
{
	return crabc_x86_64_fenv_rounding_probe();
}
#endif
