/*
 * Static Linux/x86-64 pow/powf C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive. It records both operands, result bits, the requested and
 * observed MXCSR rounding direction, and IEEE exception flags. The cases
 * cover signed-zero parity, signed integral exponents, poles, domain errors,
 * finite logarithm/exponential paths, overflow/underflow, infinities, quiet
 * NaNs, and signaling NaNs under every supported rounding direction. It
 * selects only binary64/binary32 pow: powl, public exp/log/exp2/fabs, fenv
 * policy, special math, and general libm remain outside this leaf.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#ifndef CRABC_MATH_POW_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#define POW_F64_CASES 32
#define POW_F32_CASES 32
#define POW_ROUNDING_CASES 4
#define POW_RECORD_WORDS 5
#define POW_RECORD_COUNT ((POW_F64_CASES + POW_F32_CASES) * POW_ROUNDING_CASES)
#define POW_RECORD_STORAGE_WORDS (POW_RECORD_COUNT * POW_RECORD_WORDS)

typedef double (*double_binary_function)(double, double);
typedef float (*float_binary_function)(float, float);

struct binary64_case {
	uint64_t base;
	uint64_t exponent;
};

struct binary32_case {
	uint32_t base;
	uint32_t exponent;
};

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_binary_function volatile direct_pow = (pow);
static float_binary_function volatile direct_powf = (powf);

/* The freestanding start object writes these exact 10,240 bytes with syscall. */
uint64_t crabc_x86_64_math_pow_records[POW_RECORD_STORAGE_WORDS];

static const struct binary64_case binary64_cases[POW_F64_CASES] = {
	{ UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000) },
	{ UINT64_C(0x8000000000000000), UINT64_C(0x0000000000000000) },
	{ UINT64_C(0x0000000000000000), UINT64_C(0x3ff0000000000000) },
	{ UINT64_C(0x8000000000000000), UINT64_C(0x4008000000000000) },
	{ UINT64_C(0x8000000000000000), UINT64_C(0x4000000000000000) },
	{ UINT64_C(0x0000000000000000), UINT64_C(0xbff0000000000000) },
	{ UINT64_C(0x8000000000000000), UINT64_C(0xc008000000000000) },
	{ UINT64_C(0x8000000000000000), UINT64_C(0xc000000000000000) },
	{ UINT64_C(0x3ff0000000000000), UINT64_C(0x7ff8000000000041) },
	{ UINT64_C(0xbff0000000000000), UINT64_C(0x7ff0000000000000) },
	{ UINT64_C(0xbff0000000000000), UINT64_C(0xfff0000000000000) },
	{ UINT64_C(0xc000000000000000), UINT64_C(0x4008000000000000) },
	{ UINT64_C(0xc000000000000000), UINT64_C(0x4000000000000000) },
	{ UINT64_C(0xc000000000000000), UINT64_C(0x3fe0000000000000) },
	{ UINT64_C(0x4000000000000000), UINT64_C(0x3fe0000000000000) },
	{ UINT64_C(0x4000000000000000), UINT64_C(0xbfe0000000000000) },
	{ UINT64_C(0x4000000000000000), UINT64_C(0x4024000000000000) },
	{ UINT64_C(0x4000000000000000), UINT64_C(0x4090000000000000) },
	{ UINT64_C(0x4000000000000000), UINT64_C(0xc090cc0000000000) },
	{ UINT64_C(0x7fefffffffffffff), UINT64_C(0x4000000000000000) },
	{ UINT64_C(0x0010000000000000), UINT64_C(0x4000000000000000) },
	{ UINT64_C(0x7ff0000000000000), UINT64_C(0x0000000000000000) },
	{ UINT64_C(0x7ff0000000000000), UINT64_C(0xbff0000000000000) },
	{ UINT64_C(0xfff0000000000000), UINT64_C(0x4008000000000000) },
	{ UINT64_C(0x7ff8000000000041), UINT64_C(0x4000000000000000) },
	{ UINT64_C(0x7ff0000000000042), UINT64_C(0x4000000000000000) },
	{ UINT64_C(0x4000000000000000), UINT64_C(0x7ff0000000000042) },
	{ UINT64_C(0x8000000000000000), UINT64_C(0x7ff8000000000041) },
	{ UINT64_C(0x3ff4000000000000), UINT64_C(0x4004000000000000) },
	{ UINT64_C(0x3fe0000000000000), UINT64_C(0x3ff8000000000000) },
	{ UINT64_C(0x0000000000000001), UINT64_C(0x3ff0000000000000) },
	{ UINT64_C(0x8000000000000001), UINT64_C(0x3ff0000000000000) },
};

static const struct binary32_case binary32_cases[POW_F32_CASES] = {
	{ UINT32_C(0x00000000), UINT32_C(0x00000000) },
	{ UINT32_C(0x80000000), UINT32_C(0x00000000) },
	{ UINT32_C(0x00000000), UINT32_C(0x3f800000) },
	{ UINT32_C(0x80000000), UINT32_C(0x40400000) },
	{ UINT32_C(0x80000000), UINT32_C(0x40000000) },
	{ UINT32_C(0x00000000), UINT32_C(0xbf800000) },
	{ UINT32_C(0x80000000), UINT32_C(0xc0400000) },
	{ UINT32_C(0x80000000), UINT32_C(0xc0000000) },
	{ UINT32_C(0x3f800000), UINT32_C(0x7fc00041) },
	{ UINT32_C(0xbf800000), UINT32_C(0x7f800000) },
	{ UINT32_C(0xbf800000), UINT32_C(0xff800000) },
	{ UINT32_C(0xc0000000), UINT32_C(0x40400000) },
	{ UINT32_C(0xc0000000), UINT32_C(0x40000000) },
	{ UINT32_C(0xc0000000), UINT32_C(0x3f000000) },
	{ UINT32_C(0x40000000), UINT32_C(0x3f000000) },
	{ UINT32_C(0x40000000), UINT32_C(0xbf000000) },
	{ UINT32_C(0x40000000), UINT32_C(0x41200000) },
	{ UINT32_C(0x40000000), UINT32_C(0x43000000) },
	{ UINT32_C(0x40000000), UINT32_C(0xc3160000) },
	{ UINT32_C(0x7f7fffff), UINT32_C(0x40000000) },
	{ UINT32_C(0x00800000), UINT32_C(0x40000000) },
	{ UINT32_C(0x7f800000), UINT32_C(0x00000000) },
	{ UINT32_C(0x7f800000), UINT32_C(0xbf800000) },
	{ UINT32_C(0xff800000), UINT32_C(0x40400000) },
	{ UINT32_C(0x7fc00041), UINT32_C(0x40000000) },
	{ UINT32_C(0x7f800042), UINT32_C(0x40000000) },
	{ UINT32_C(0x40000000), UINT32_C(0x7f800042) },
	{ UINT32_C(0x80000000), UINT32_C(0x7fc00041) },
	{ UINT32_C(0x3fa00000), UINT32_C(0x40200000) },
	{ UINT32_C(0x3f000000), UINT32_C(0x3fc00000) },
	{ UINT32_C(0x00000001), UINT32_C(0x3f800000) },
	{ UINT32_C(0x80000001), UINT32_C(0x3f800000) },
};

static const int rounding_modes[POW_ROUNDING_CASES] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

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

static int record_binary64(size_t *cursor, int rounding_mode,
	const struct binary64_case *test_case)
{
	double result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	result = direct_pow(double_from_bits(test_case->base),
		double_from_bits(test_case->exponent));
	if (*cursor + POW_RECORD_WORDS > POW_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_pow_records[(*cursor)++] = test_case->base;
	crabc_x86_64_math_pow_records[(*cursor)++] = test_case->exponent;
	crabc_x86_64_math_pow_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_pow_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_pow_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode,
	const struct binary32_case *test_case)
{
	float result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	result = direct_powf(float_from_bits(test_case->base),
		float_from_bits(test_case->exponent));
	if (*cursor + POW_RECORD_WORDS > POW_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_pow_records[(*cursor)++] =
		UINT64_C(0x0000000100000000) | test_case->base;
	crabc_x86_64_math_pow_records[(*cursor)++] = test_case->exponent;
	crabc_x86_64_math_pow_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_pow_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_pow_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

int crabc_x86_64_math_pow_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t case_index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < POW_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (case_index = 0; case_index < POW_F64_CASES && status == 0;
			case_index++)
			status = record_binary64(&cursor, rounding_modes[mode_index],
				&binary64_cases[case_index]);
		for (case_index = 0; case_index < POW_F32_CASES && status == 0;
			case_index++)
			status = record_binary32(&cursor, rounding_modes[mode_index],
				&binary32_cases[case_index]);
	}
	if (cursor != POW_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_POW_FREESTANDING
static int write_all(const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;

	while (length != 0) {
		ssize_t written = write(1, cursor, length);

		if (written <= 0)
			return 1;
		cursor += written;
		length -= (size_t)written;
	}
	return 0;
}

int main(void)
{
	int status = crabc_x86_64_math_pow_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_pow_records,
		sizeof(crabc_x86_64_math_pow_records));
}
#endif
