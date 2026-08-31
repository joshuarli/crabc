/*
 * Static Linux/x86-64 GNU exp10/pow10 C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive. It calls both same-address names under every MXCSR rounding
 * direction and records input/result bits plus IEEE exception flags around the
 * integer-table, fractional-exp2, pow, overflow/underflow, signed-zero,
 * infinity, quiet-NaN, and signaling-NaN paths. It selects only binary64 GNU
 * decimal exponentiation: binary32 exp10f/pow10f, all long-double variants,
 * fenv policy, special math, and general libm remain outside this leaf.
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
#ifndef CRABC_MATH_EXP10_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#define EXP10_F64_CASES 32
#define EXP10_ALIASES 2
#define EXP10_ROUNDING_CASES 4
#define EXP10_RECORD_WORDS 4
#define EXP10_RECORD_COUNT (EXP10_F64_CASES * EXP10_ALIASES * EXP10_ROUNDING_CASES)
#define EXP10_RECORD_STORAGE_WORDS (EXP10_RECORD_COUNT * EXP10_RECORD_WORDS)

typedef double (*double_unary_function)(double);

/* Parentheses force calls through the declared C ABI rather than builtins. */
static double_unary_function volatile direct_exp10 = (exp10);
static double_unary_function volatile direct_pow10 = (pow10);

/* The freestanding start object writes these exact 8,192 bytes with syscall. */
uint64_t crabc_x86_64_math_exp10_records[EXP10_RECORD_STORAGE_WORDS];

static const uint64_t binary64_inputs[EXP10_F64_CASES] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x8000000000000001),
	UINT64_C(0x000fffffffffffff), UINT64_C(0x0010000000000000),
	UINT64_C(0x8010000000000000), UINT64_C(0x3fe0000000000000),
	UINT64_C(0xbfe0000000000000), UINT64_C(0xbff0000000000000),
	UINT64_C(0x3fefffffffffffff), UINT64_C(0x3ff0000000000000),
	UINT64_C(0x3ff0000000000001), UINT64_C(0x402dffffffffffff),
	UINT64_C(0x402e000000000000), UINT64_C(0x402f000000000000),
	UINT64_C(0x4030000000000000), UINT64_C(0x4030000000000001),
	UINT64_C(0xc02e000000000000), UINT64_C(0xc02f000000000000),
	UINT64_C(0xc030000000000000), UINT64_C(0xc030000000000001),
	UINT64_C(0x4073400000000000), UINT64_C(0x4073500000000000),
	UINT64_C(0xc074300000000000), UINT64_C(0xc074400000000000),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0xffefffffffffffff),
	UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
	UINT64_C(0x7ff8000000000041), UINT64_C(0x7ff0000000000042),
};

static const int rounding_modes[EXP10_ROUNDING_CASES] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

static uint64_t double_bits(double value)
{
	union { double value; uint64_t bits; } view = { .value = value };
	return view.bits;
}

static double double_from_bits(uint64_t bits)
{
	union { double value; uint64_t bits; } view = { .bits = bits };
	return view.value;
}

static int record_binary64(size_t *cursor, int rounding_mode,
	unsigned int alias_index, uint64_t input)
{
	double result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	if (alias_index == 0)
		result = direct_exp10(double_from_bits(input));
	else
		result = direct_pow10(double_from_bits(input));
	if (*cursor + EXP10_RECORD_WORDS > EXP10_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_exp10_records[(*cursor)++] =
		((uint64_t)(alias_index + 1) << 32) | input;
	crabc_x86_64_math_exp10_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_exp10_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_exp10_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

int crabc_x86_64_math_exp10_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	unsigned int alias_index;
	int status = 0;

	if (direct_exp10 != direct_pow10)
		return 1;
	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 2;
	for (mode_index = 0; mode_index < EXP10_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (alias_index = 0; alias_index < EXP10_ALIASES && status == 0;
			alias_index++) {
			for (input_index = 0; input_index < EXP10_F64_CASES && status == 0;
				input_index++)
				status = record_binary64(&cursor, rounding_modes[mode_index],
					alias_index, binary64_inputs[input_index]);
		}
	}
	if (cursor != EXP10_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_EXP10_FREESTANDING
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
	int status = crabc_x86_64_math_exp10_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_exp10_records,
		sizeof(crabc_x86_64_math_exp10_records));
}
#endif
