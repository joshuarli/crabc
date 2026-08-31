/*
 * Static Linux/x86-64 atanh/atanhf C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive. It records result bits and IEEE exception flags under each
 * MXCSR rounding direction, including the source's subnormal force-evaluation,
 * tiny-input and half branches, pole/domain neighborhoods, signed zero,
 * infinite, quiet-NaN, and signaling-NaN inputs. It selects only
 * binary64/binary32 inverse hyperbolic tangent: atanhl, fenv policy,
 * special/complex math, and general libm remain outside this leaf.
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
#ifndef CRABC_MATH_ATANH_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#define ATANH_F64_CASES 32
#define ATANH_F32_CASES 32
#define ATANH_ROUNDING_CASES 4
#define ATANH_RECORD_WORDS 4
#define ATANH_RECORD_COUNT ((ATANH_F64_CASES + ATANH_F32_CASES) * ATANH_ROUNDING_CASES)
#define ATANH_RECORD_STORAGE_WORDS (ATANH_RECORD_COUNT * ATANH_RECORD_WORDS)

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_unary_function volatile direct_atanh = (atanh);
static float_unary_function volatile direct_atanhf = (atanhf);

/* The freestanding start object writes these exact 8,192 bytes with syscall. */
uint64_t crabc_x86_64_math_atanh_records[ATANH_RECORD_STORAGE_WORDS];

static const uint64_t binary64_inputs[ATANH_F64_CASES] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x000fffffffffffff),
	UINT64_C(0x0010000000000000), UINT64_C(0x3de0000000000000),
	UINT64_C(0x3df0000000000000), UINT64_C(0x3df0000000000001),
	UINT64_C(0x3fd0000000000000), UINT64_C(0x3fdfffffffffffff),
	UINT64_C(0x3fe0000000000000), UINT64_C(0x3fe0000000000001),
	UINT64_C(0x3fe8000000000000), UINT64_C(0x3fefffffffffffff),
	UINT64_C(0x3ff0000000000000), UINT64_C(0x3ff0000000000001),
	UINT64_C(0x7ff0000000000000), UINT64_C(0x7ff8000000000041),
	UINT64_C(0x7ff0000000000042), UINT64_C(0x8000000000000001),
	UINT64_C(0xbdf0000000000000), UINT64_C(0xbfd0000000000000),
	UINT64_C(0xbfe0000000000001), UINT64_C(0xbfe8000000000000),
	UINT64_C(0xbfefffffffffffff), UINT64_C(0xbff0000000000000),
	UINT64_C(0xbff0000000000001), UINT64_C(0xfff0000000000000),
	UINT64_C(0xfff8000000000041), UINT64_C(0xfff0000000000042),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0xffefffffffffffff),
};

static const uint32_t binary32_inputs[ATANH_F32_CASES] = {
	UINT32_C(0x00000000), UINT32_C(0x80000000), UINT32_C(0x00000001),
	UINT32_C(0x007fffff), UINT32_C(0x00800000), UINT32_C(0x2f000000),
	UINT32_C(0x2f800000), UINT32_C(0x2f800001), UINT32_C(0x3e800000),
	UINT32_C(0x3effffff), UINT32_C(0x3f000000), UINT32_C(0x3f000001),
	UINT32_C(0x3f400000), UINT32_C(0x3f7fffff), UINT32_C(0x3f800000),
	UINT32_C(0x3f800001), UINT32_C(0x7f800000), UINT32_C(0x7fc00041),
	UINT32_C(0x7f800042), UINT32_C(0x80000001), UINT32_C(0xaf800000),
	UINT32_C(0xbe800000), UINT32_C(0xbf000001), UINT32_C(0xbf400000),
	UINT32_C(0xbf7fffff), UINT32_C(0xbf800000), UINT32_C(0xbf800001),
	UINT32_C(0xff800000), UINT32_C(0xffc00041), UINT32_C(0xff800042),
	UINT32_C(0x7f7fffff), UINT32_C(0xff7fffff),
};

static const int rounding_modes[ATANH_ROUNDING_CASES] = {
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

static int record_binary64(size_t *cursor, int rounding_mode, uint64_t input)
{
	double result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	result = direct_atanh(double_from_bits(input));
	if (*cursor + ATANH_RECORD_WORDS > ATANH_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_atanh_records[(*cursor)++] = input;
	crabc_x86_64_math_atanh_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_atanh_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_atanh_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode, uint32_t input)
{
	float result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	result = direct_atanhf(float_from_bits(input));
	if (*cursor + ATANH_RECORD_WORDS > ATANH_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_atanh_records[(*cursor)++] =
		UINT64_C(0x0000000100000000) | input;
	crabc_x86_64_math_atanh_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_atanh_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_atanh_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

int crabc_x86_64_math_atanh_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < ATANH_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (input_index = 0; input_index < ATANH_F64_CASES && status == 0;
			input_index++)
			status = record_binary64(&cursor, rounding_modes[mode_index],
				binary64_inputs[input_index]);
		for (input_index = 0; input_index < ATANH_F32_CASES && status == 0;
			input_index++)
			status = record_binary32(&cursor, rounding_modes[mode_index],
				binary32_inputs[input_index]);
	}
	if (cursor != ATANH_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_ATANH_FREESTANDING
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
	int status = crabc_x86_64_math_atanh_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_atanh_records,
		sizeof(crabc_x86_64_math_atanh_records));
}
#endif
