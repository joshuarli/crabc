/*
 * Static Linux/x86-64 sin/sinf C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive. It records result bits and IEEE exception flags under each
 * MXCSR rounding direction, including tiny/subnormal inputs, all argument
 * reduction paths, signed zero, infinite, quiet-NaN, and signaling-NaN
 * inputs. It selects only binary64/binary32 sine: sinl, sincos, fenv policy,
 * special math, and general libm remain outside this leaf.
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
#ifndef CRABC_MATH_SIN_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#define SIN_F64_CASES 32
#define SIN_F32_CASES 32
#define SIN_ROUNDING_CASES 4
#define SIN_RECORD_WORDS 4
#define SIN_RECORD_COUNT ((SIN_F64_CASES + SIN_F32_CASES) * SIN_ROUNDING_CASES)
#define SIN_RECORD_STORAGE_WORDS (SIN_RECORD_COUNT * SIN_RECORD_WORDS)

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_unary_function volatile direct_sin = (sin);
static float_unary_function volatile direct_sinf = (sinf);

/* The freestanding start object writes these exact 8,192 bytes with syscall. */
uint64_t crabc_x86_64_math_sin_records[SIN_RECORD_STORAGE_WORDS];

static const uint64_t binary64_inputs[SIN_F64_CASES] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x000fffffffffffff),
	UINT64_C(0x0010000000000000), UINT64_C(0x3e30000000000000),
	UINT64_C(0x3e50000000000000), UINT64_C(0x3ff0000000000000),
	UINT64_C(0x3fe0c152382d7366), UINT64_C(0x3fe921fb54442d18),
	UINT64_C(0x3ff921fb54442d17), UINT64_C(0x3ff921fb54442d18),
	UINT64_C(0x3ff921fb54442d19), UINT64_C(0x400921fb54442d18),
	UINT64_C(0x4012d97c7f3321d2), UINT64_C(0x401921fb54442d18),
	UINT64_C(0x41d0000000000000), UINT64_C(0x4415af1d78b58c40),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0x7ff0000000000000),
	UINT64_C(0x7ff8000000000041), UINT64_C(0x7ff0000000000042),
	UINT64_C(0x8000000000000001), UINT64_C(0xbfe0c152382d7366),
	UINT64_C(0xbff921fb54442d18), UINT64_C(0xc00921fb54442d18),
	UINT64_C(0xc012d97c7f3321d2), UINT64_C(0xc01921fb54442d18),
	UINT64_C(0xc1d0000000000000), UINT64_C(0xc415af1d78b58c40),
	UINT64_C(0xffefffffffffffff), UINT64_C(0xfff0000000000000),
};

static const uint32_t binary32_inputs[SIN_F32_CASES] = {
	UINT32_C(0x00000000), UINT32_C(0x80000000), UINT32_C(0x00000001),
	UINT32_C(0x007fffff), UINT32_C(0x00800000), UINT32_C(0x38800000),
	UINT32_C(0x39800000), UINT32_C(0x3f800000), UINT32_C(0x3f060a92),
	UINT32_C(0x3f490fdb), UINT32_C(0x3fc90fda), UINT32_C(0x3fc90fdb),
	UINT32_C(0x3fc90fdc), UINT32_C(0x40490fdb), UINT32_C(0x4096cbe4),
	UINT32_C(0x40c90fdb), UINT32_C(0x49800000), UINT32_C(0x60ad78ec),
	UINT32_C(0x7f7fffff), UINT32_C(0x7f800000), UINT32_C(0x7fc00041),
	UINT32_C(0x7f800042), UINT32_C(0x80000001), UINT32_C(0xbf060a92),
	UINT32_C(0xbfc90fdb), UINT32_C(0xc0490fdb), UINT32_C(0xc096cbe4),
	UINT32_C(0xc0c90fdb), UINT32_C(0xc9800000), UINT32_C(0xe0ad78ec),
	UINT32_C(0xff7fffff), UINT32_C(0xff800000),
};

static const int rounding_modes[SIN_ROUNDING_CASES] = {
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
	result = direct_sin(double_from_bits(input));
	if (*cursor + SIN_RECORD_WORDS > SIN_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_sin_records[(*cursor)++] = input;
	crabc_x86_64_math_sin_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_sin_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_sin_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode, uint32_t input)
{
	float result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	result = direct_sinf(float_from_bits(input));
	if (*cursor + SIN_RECORD_WORDS > SIN_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_sin_records[(*cursor)++] =
		UINT64_C(0x0000000100000000) | input;
	crabc_x86_64_math_sin_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_sin_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_sin_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

int crabc_x86_64_math_sin_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < SIN_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (input_index = 0; input_index < SIN_F64_CASES && status == 0;
			input_index++)
			status = record_binary64(&cursor, rounding_modes[mode_index],
				binary64_inputs[input_index]);
		for (input_index = 0; input_index < SIN_F32_CASES && status == 0;
			input_index++)
			status = record_binary32(&cursor, rounding_modes[mode_index],
				binary32_inputs[input_index]);
	}
	if (cursor != SIN_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_SIN_FREESTANDING
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
	int status = crabc_x86_64_math_sin_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_sin_records,
		sizeof(crabc_x86_64_math_sin_records));
}
#endif
