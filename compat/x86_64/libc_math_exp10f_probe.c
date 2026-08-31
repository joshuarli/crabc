/*
 * Static Linux/x86-64 GNU exp10f/pow10f C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive.  It calls both names under every MXCSR rounding direction
 * and records result bits and IEEE exception flags around the integer-table,
 * fractional-exp2, overflow/underflow, signed-zero, infinity, and NaN paths.
 * It selects only binary32 GNU decimal exponentiation and musl's weak
 * same-address alias: binary64 exp10/pow10, all long-double variants, fenv
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
#ifndef CRABC_MATH_EXP10F_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#if FLT_EVAL_METHOD != 0
#error "the raw binary32 fixture requires SSE evaluation"
#endif

#define EXP10F_F32_CASES 32
#define EXP10F_ALIASES 2
#define EXP10F_ROUNDING_CASES 4
#define EXP10F_RECORD_WORDS 4
#define EXP10F_RECORD_COUNT (EXP10F_F32_CASES * EXP10F_ALIASES * EXP10F_ROUNDING_CASES)
#define EXP10F_RECORD_STORAGE_WORDS (EXP10F_RECORD_COUNT * EXP10F_RECORD_WORDS)

typedef float (*float_unary_function)(float);

/* Parentheses force calls through the declared C ABI rather than builtins. */
static float_unary_function volatile direct_exp10f = (exp10f);
static float_unary_function volatile direct_pow10f = (pow10f);

/* The freestanding start object writes these exact 8,192 bytes with syscall. */
uint64_t crabc_x86_64_math_exp10f_records[EXP10F_RECORD_STORAGE_WORDS];

static const uint32_t binary32_inputs[EXP10F_F32_CASES] = {
	UINT32_C(0x00000000), UINT32_C(0x80000000), UINT32_C(0x00000001),
	UINT32_C(0x80000001), UINT32_C(0x007fffff), UINT32_C(0x00800000),
	UINT32_C(0x3f000000), UINT32_C(0xbf000000), UINT32_C(0xbf800000),
	UINT32_C(0x3f7fffff), UINT32_C(0x3f800000), UINT32_C(0x3f800001),
	UINT32_C(0x40dfffff), UINT32_C(0x40e00000), UINT32_C(0x40e00001),
	UINT32_C(0xc0e00000), UINT32_C(0x40ffffff), UINT32_C(0x41000000),
	UINT32_C(0x41000001), UINT32_C(0xc1000000), UINT32_C(0x42180000),
	UINT32_C(0x421c0000), UINT32_C(0xc2140000), UINT32_C(0xc2180000),
	UINT32_C(0xc2300000), UINT32_C(0xc2340000), UINT32_C(0x7f7fffff),
	UINT32_C(0xff7fffff), UINT32_C(0x7f800000), UINT32_C(0xff800000),
	UINT32_C(0x7fc00041), UINT32_C(0x7f800042),
};

static const int rounding_modes[EXP10F_ROUNDING_CASES] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

static uint32_t float_bits(float value)
{
	union { float value; uint32_t bits; } view = { .value = value };
	return view.bits;
}

static float float_from_bits(uint32_t bits)
{
	union { float value; uint32_t bits; } view = { .bits = bits };
	return view.value;
}

static int record_binary32(size_t *cursor, int rounding_mode,
	unsigned int alias_index, uint32_t input)
{
	float result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	if (alias_index == 0)
		result = direct_exp10f(float_from_bits(input));
	else
		result = direct_pow10f(float_from_bits(input));
	if (*cursor + EXP10F_RECORD_WORDS > EXP10F_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_exp10f_records[(*cursor)++] =
		((uint64_t)(alias_index + 1) << 32) | input;
	crabc_x86_64_math_exp10f_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_exp10f_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_exp10f_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

int crabc_x86_64_math_exp10f_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	unsigned int alias_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < EXP10F_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (alias_index = 0; alias_index < EXP10F_ALIASES && status == 0;
			alias_index++) {
			for (input_index = 0; input_index < EXP10F_F32_CASES && status == 0;
				input_index++)
				status = record_binary32(&cursor, rounding_modes[mode_index],
					alias_index, binary32_inputs[input_index]);
		}
	}
	if (cursor != EXP10F_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_EXP10F_FREESTANDING
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
	int status = crabc_x86_64_math_exp10f_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_exp10f_records,
		sizeof(crabc_x86_64_math_exp10f_records));
}
#endif
