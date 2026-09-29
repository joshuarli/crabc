/*
 * Static Linux/x86-64 exp2/exp2f C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive. It records result bits, IEEE exception flags, and errno
 * under each MXCSR rounding direction, including tiny, subnormal, boundary,
 * infinite, quiet-NaN, and signaling-NaN inputs. It selects the binary64/binary32
 * base-two exponential pair: `exp2l`, fenv policy/APIs, special math, and
 * general libm remain outside this artifact.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <float.h>
#include <math.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#ifndef CRABC_MATH_EXP2_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#define EXP2_F64_CASES 47
#define EXP2_F32_CASES 43
#define EXP2_F64_TABLE_CASES (512 * 2 * 3)
#define EXP2_F32_TABLE_CASES (128 * 2 * 3)
#define EXP2_ROUNDING_CASES 4
#define EXP2_RECORD_WORDS 4
#define EXP2_RECORD_COUNT \
	((EXP2_F64_CASES + EXP2_F32_CASES + EXP2_F64_TABLE_CASES + \
	  EXP2_F32_TABLE_CASES) * EXP2_ROUNDING_CASES)
#define EXP2_RECORD_STORAGE_WORDS (EXP2_RECORD_COUNT * EXP2_RECORD_WORDS)

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_unary_function volatile direct_exp2 = (exp2);
static float_unary_function volatile direct_exp2f = (exp2f);

/* The freestanding start object writes the selected corpus with syscall. */
uint64_t crabc_x86_64_math_exp2_records[EXP2_RECORD_STORAGE_WORDS];
const uint64_t crabc_x86_64_math_exp2_record_bytes =
	sizeof(crabc_x86_64_math_exp2_records);

static const uint64_t binary64_inputs[EXP2_F64_CASES] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x8000000000000001),
	UINT64_C(0x000fffffffffffff), UINT64_C(0x0010000000000000),
	UINT64_C(0x8010000000000000), UINT64_C(0x3c80000000000000),
	UINT64_C(0x3c90000000000000), UINT64_C(0xbc90000000000000),
	UINT64_C(0xc090cc0000000000), UINT64_C(0xc090c80000000000),
	UINT64_C(0xc08ff80000000000), UINT64_C(0xc08ff00000000000),
	UINT64_C(0xbff0000000000000), UINT64_C(0xbfe0000000000000),
	UINT64_C(0x3fe0000000000000), UINT64_C(0x3ff0000000000000),
	UINT64_C(0x4000000000000000), UINT64_C(0x4024000000000000),
	UINT64_C(0x405fc00000000000), UINT64_C(0x4060000000000000),
	UINT64_C(0x407ff00000000000), UINT64_C(0x408d000000000000),
	UINT64_C(0x408ff80000000000), UINT64_C(0x4090000000000000),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0x7ff0000000000000),
	UINT64_C(0xfff0000000000000), UINT64_C(0x7ff8000000000041),
	UINT64_C(0x7ff0000000000042),
	/* Adjacent inputs straddle underflow, normal, overflow, and reduction edges. */
	UINT64_C(0xc090cbffffffffff), UINT64_C(0xc090cc0000000001),
	UINT64_C(0xc090c7ffffffffff), UINT64_C(0xc090c80000000001),
	UINT64_C(0xc08fefffffffffff), UINT64_C(0xc08ff00000000001),
	UINT64_C(0x408fffffffffffff), UINT64_C(0x4090000000000001),
	UINT64_C(0xc08ffbffffffffff), UINT64_C(0xc08ffc0000000001),
	UINT64_C(0x408ffbffffffffff), UINT64_C(0x408ffc0000000001),
	UINT64_C(0xbf8fffffffffffff), UINT64_C(0xbf90000000000001),
	UINT64_C(0x3f8fffffffffffff), UINT64_C(0x3f90000000000001),
};

static const uint32_t binary32_inputs[EXP2_F32_CASES] = {
	UINT32_C(0x00000000), UINT32_C(0x80000000), UINT32_C(0x00000001),
	UINT32_C(0x80000001), UINT32_C(0x007fffff), UINT32_C(0x00800000),
	UINT32_C(0x80800000), UINT32_C(0xc3160000), UINT32_C(0xc3150000),
	UINT32_C(0xc3000000), UINT32_C(0xc2fe0000), UINT32_C(0xbf800000),
	UINT32_C(0xbf000000), UINT32_C(0x3f000000), UINT32_C(0x3f800000),
	UINT32_C(0x40000000), UINT32_C(0x41200000), UINT32_C(0x41fc0000),
	UINT32_C(0x42800000), UINT32_C(0x42fe0000), UINT32_C(0x43000000),
	UINT32_C(0x7f7fffff), UINT32_C(0x7f800000), UINT32_C(0xff800000),
	UINT32_C(0x7fc00041), UINT32_C(0x7f800042), UINT32_C(0xff7fffff),
	UINT32_C(0xc315ffff), UINT32_C(0xc3160001),
	UINT32_C(0xc314ffff), UINT32_C(0xc3150001),
	UINT32_C(0xc2fbffff), UINT32_C(0xc2fc0001),
	UINT32_C(0x42ffffff), UINT32_C(0x43000001),
	UINT32_C(0xc2feffff), UINT32_C(0xc2ff0001),
	UINT32_C(0x42feffff), UINT32_C(0x42ff0001),
	UINT32_C(0xbcffffff), UINT32_C(0xbd000001),
	UINT32_C(0x3cffffff), UINT32_C(0x3d000001),
};

static const int rounding_modes[EXP2_ROUNDING_CASES] = {
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
	errno = 123;
	result = direct_exp2(double_from_bits(input));
	if (*cursor + EXP2_RECORD_WORDS > EXP2_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_exp2_records[(*cursor)++] = input;
	crabc_x86_64_math_exp2_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_exp2_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_exp2_records[(*cursor)++] =
		((uint64_t)(uint32_t)errno << 32) |
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode, uint32_t input)
{
	float result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	errno = 123;
	result = direct_exp2f(float_from_bits(input));
	if (*cursor + EXP2_RECORD_WORDS > EXP2_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_exp2_records[(*cursor)++] =
		UINT64_C(0x0000000100000000) | input;
	crabc_x86_64_math_exp2_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_exp2_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_exp2_records[(*cursor)++] =
		((uint64_t)(uint32_t)errno << 32) |
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

int crabc_x86_64_math_exp2_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < EXP2_ROUNDING_CASES && status == 0;
		mode_index++) {
		int table_index;
		int position;
		int neighbor;
		uint64_t bits64;
		uint32_t bits32;

		for (input_index = 0; input_index < EXP2_F64_CASES && status == 0;
			input_index++)
			status = record_binary64(&cursor, rounding_modes[mode_index],
				binary64_inputs[input_index]);
		for (input_index = 0; input_index < EXP2_F32_CASES && status == 0;
			input_index++)
			status = record_binary32(&cursor, rounding_modes[mode_index],
				binary32_inputs[input_index]);
		/* The two kernels reduce on 1/128 and 1/32 grids. Probe every
		 * grid point and midpoint with its two adjacent representations. */
		for (table_index = -256; table_index < 256 && status == 0;
			table_index++) {
			for (position = 0; position < 2 && status == 0; position++) {
				bits64 = double_bits((double)(2 * table_index + position) / 256.0);
				for (neighbor = -1; neighbor <= 1 && status == 0; neighbor++)
					status = record_binary64(&cursor, rounding_modes[mode_index],
						bits64 == 0 && neighbor == -1 ?
						UINT64_C(0x8000000000000001) : bits64 + neighbor);
			}
		}
		for (table_index = -64; table_index < 64 && status == 0;
			table_index++) {
			for (position = 0; position < 2 && status == 0; position++) {
				bits32 = float_bits((float)(2 * table_index + position) / 64.0f);
				for (neighbor = -1; neighbor <= 1 && status == 0; neighbor++)
					status = record_binary32(&cursor, rounding_modes[mode_index],
						bits32 == 0 && neighbor == -1 ?
						UINT32_C(0x80000001) : bits32 + neighbor);
			}
		}
	}
	if (cursor != EXP2_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_EXP2_FREESTANDING
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
	int status = crabc_x86_64_math_exp2_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_exp2_records,
		sizeof(crabc_x86_64_math_exp2_records));
}
#endif
