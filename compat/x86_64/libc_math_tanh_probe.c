/*
 * Static Linux/x86-64 tanh/tanhf C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive. It records result bits and IEEE exception flags under each
 * MXCSR rounding direction, including the source's subnormal force-evaluation,
 * branch thresholds, saturation, signed zero, infinite, quiet-NaN, and
 * signaling-NaN inputs. It selects only binary64/binary32 hyperbolic tangent:
 * tanhl, fenv policy, special/complex math, and general libm remain outside
 * this leaf.
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
#ifndef CRABC_MATH_TANH_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#define TANH_F64_CASES 32
#define TANH_F32_CASES 32
#define TANH_ROUNDING_CASES 4
#define TANH_RECORD_WORDS 4
#define TANH_RECORD_COUNT ((TANH_F64_CASES + TANH_F32_CASES) * TANH_ROUNDING_CASES)
#define TANH_RECORD_STORAGE_WORDS (TANH_RECORD_COUNT * TANH_RECORD_WORDS)

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_unary_function volatile direct_tanh = (tanh);
static float_unary_function volatile direct_tanhf = (tanhf);

/* The freestanding start object writes these exact 8,192 bytes with syscall. */
uint64_t crabc_x86_64_math_tanh_records[TANH_RECORD_STORAGE_WORDS];

static const uint64_t binary64_inputs[TANH_F64_CASES] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x000fffffffffffff),
	UINT64_C(0x0010000000000000), UINT64_C(0x3c80000000000000),
	UINT64_C(0x3fd058ad00000000), UINT64_C(0x3fd058ae00000000),
	UINT64_C(0x3fd058af00000000), UINT64_C(0x3fe193e900000000),
	UINT64_C(0x3fe193ea00000000), UINT64_C(0x3fe193eb00000000),
	UINT64_C(0x3ff0000000000000), UINT64_C(0x4033ffffffffffff),
	UINT64_C(0x4034000000000000), UINT64_C(0x4034000000000001),
	UINT64_C(0x4035000000000000), UINT64_C(0x7fefffffffffffff),
	UINT64_C(0x7ff0000000000000), UINT64_C(0x7ff8000000000041),
	UINT64_C(0x7ff0000000000042), UINT64_C(0x8000000000000001),
	UINT64_C(0xbfd058ae00000000), UINT64_C(0xbfe193ea00000000),
	UINT64_C(0xbff0000000000000), UINT64_C(0xc033ffffffffffff),
	UINT64_C(0xc034000000000000), UINT64_C(0xc034000000000001),
	UINT64_C(0xc035000000000000), UINT64_C(0xffefffffffffffff),
	UINT64_C(0xfff0000000000000), UINT64_C(0xfff8000000000041),
};

static const uint32_t binary32_inputs[TANH_F32_CASES] = {
	UINT32_C(0x00000000), UINT32_C(0x80000000), UINT32_C(0x00000001),
	UINT32_C(0x007fffff), UINT32_C(0x00800000), UINT32_C(0x33800000),
	UINT32_C(0x3e82c577), UINT32_C(0x3e82c578), UINT32_C(0x3e82c579),
	UINT32_C(0x3f0c9f53), UINT32_C(0x3f0c9f54), UINT32_C(0x3f0c9f55),
	UINT32_C(0x3f800000), UINT32_C(0x411fffff), UINT32_C(0x41200000),
	UINT32_C(0x41200001), UINT32_C(0x41300000), UINT32_C(0x7f7fffff),
	UINT32_C(0x7f800000), UINT32_C(0x7fc00041), UINT32_C(0x7f800042),
	UINT32_C(0x80000001), UINT32_C(0xbe82c578), UINT32_C(0xbf0c9f54),
	UINT32_C(0xbf800000), UINT32_C(0xc11fffff), UINT32_C(0xc1200000),
	UINT32_C(0xc1200001), UINT32_C(0xc1300000), UINT32_C(0xff7fffff),
	UINT32_C(0xff800000), UINT32_C(0xffc00041),
};

static const int rounding_modes[TANH_ROUNDING_CASES] = {
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
	result = direct_tanh(double_from_bits(input));
	if (*cursor + TANH_RECORD_WORDS > TANH_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_tanh_records[(*cursor)++] = input;
	crabc_x86_64_math_tanh_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_tanh_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_tanh_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode, uint32_t input)
{
	float result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	result = direct_tanhf(float_from_bits(input));
	if (*cursor + TANH_RECORD_WORDS > TANH_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_tanh_records[(*cursor)++] =
		UINT64_C(0x0000000100000000) | input;
	crabc_x86_64_math_tanh_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_tanh_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_tanh_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

int crabc_x86_64_math_tanh_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < TANH_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (input_index = 0; input_index < TANH_F64_CASES && status == 0;
			input_index++)
			status = record_binary64(&cursor, rounding_modes[mode_index],
				binary64_inputs[input_index]);
		for (input_index = 0; input_index < TANH_F32_CASES && status == 0;
			input_index++)
			status = record_binary32(&cursor, rounding_modes[mode_index],
				binary32_inputs[input_index]);
	}
	if (cursor != TANH_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_TANH_FREESTANDING
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
	int status = crabc_x86_64_math_tanh_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_tanh_records,
		sizeof(crabc_x86_64_math_tanh_records));
}
#endif
