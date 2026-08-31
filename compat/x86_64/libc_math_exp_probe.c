/*
 * Static Linux/x86-64 exp/expf C ABI differential regression.
 *
 * This raw-bit corpus runs first through pinned musl 1.2.6 and then through
 * one freestanding crabc archive. It records results and IEEE exception flags
 * under every rounding direction. The record carries both the requested and
 * observed modes, so a candidate cannot inherit a different ambient MXCSR
 * direction. It selects only binary64 `exp` and binary32 `expf`; binary80,
 * exp-family completion, fenv policy, and all other libm entries remain
 * outside this artifact.
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
#ifndef CRABC_MATH_EXP_FREESTANDING
#include <unistd.h>
#endif

#if FLT_EVAL_METHOD != 0
#error "the raw binary32/binary64 fixture requires SSE evaluation"
#endif

#define EXP_F64_CASES 27
#define EXP_F32_CASES 27
#define EXP_ROUNDING_CASES 4
#define EXP_RECORD_WORDS 4
#define EXP_RECORD_COUNT ((EXP_F64_CASES + EXP_F32_CASES) * EXP_ROUNDING_CASES)
#define EXP_RECORD_STORAGE_WORDS (EXP_RECORD_COUNT * EXP_RECORD_WORDS)

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_unary_function volatile direct_exp = (exp);
static float_unary_function volatile direct_expf = (expf);

/* The freestanding start object writes these exact 6,912 bytes with syscall. */
uint64_t crabc_x86_64_math_exp_records[EXP_RECORD_STORAGE_WORDS];

static const uint64_t binary64_inputs[EXP_F64_CASES] = {
	UINT64_C(0x8000000000000000), UINT64_C(0x0000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x8000000000000001),
	UINT64_C(0x3c80000000000000), UINT64_C(0xbc80000000000000),
	UINT64_C(0x3c90000000000000), UINT64_C(0xbc90000000000000),
	UINT64_C(0x3fe0000000000000), UINT64_C(0xbfe0000000000000),
	UINT64_C(0x3ff0000000000000), UINT64_C(0xbff0000000000000),
	UINT64_C(0x3fe62e42fefa39ef), UINT64_C(0xbfe62e42fefa39ef),
	UINT64_C(0x4080000000000000), UINT64_C(0xc080000000000000),
	UINT64_C(0x40862e42fefa39ee), UINT64_C(0x40862e42fefa39ef),
	UINT64_C(0x408fffffffffffff), UINT64_C(0x4090000000000000),
	UINT64_C(0xc087480000000000), UINT64_C(0xc090000000000000),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0x7ff0000000000000),
	UINT64_C(0xfff0000000000000), UINT64_C(0x7ff8000000000041),
	UINT64_C(0x7ff0000000000042),
};

static const uint32_t binary32_inputs[EXP_F32_CASES] = {
	UINT32_C(0x80000000), UINT32_C(0x00000000), UINT32_C(0x00000001),
	UINT32_C(0x80000001), UINT32_C(0x32000000), UINT32_C(0xb2000000),
	UINT32_C(0x33800000), UINT32_C(0xb3800000), UINT32_C(0x3f000000),
	UINT32_C(0xbf000000), UINT32_C(0x3f800000), UINT32_C(0xbf800000),
	UINT32_C(0x3f317218), UINT32_C(0xbf317218), UINT32_C(0x42b00000),
	UINT32_C(0xc2b00000), UINT32_C(0x42b17217), UINT32_C(0x42b17219),
	UINT32_C(0x42b20000), UINT32_C(0xc2ce0000), UINT32_C(0xc2d00000),
	UINT32_C(0x7f7fffff), UINT32_C(0x7f800000), UINT32_C(0xff800000),
	UINT32_C(0x7fc00041), UINT32_C(0x7f800042), UINT32_C(0x41200000),
};

static const int rounding_modes[EXP_ROUNDING_CASES] = {
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
	result = direct_exp(double_from_bits(input));
	if (*cursor + EXP_RECORD_WORDS > EXP_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_exp_records[(*cursor)++] = input;
	crabc_x86_64_math_exp_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_exp_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_exp_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode, uint32_t input)
{
	float result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	result = direct_expf(float_from_bits(input));
	if (*cursor + EXP_RECORD_WORDS > EXP_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_exp_records[(*cursor)++] =
		UINT64_C(0x0000000100000000) | input;
	crabc_x86_64_math_exp_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_exp_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_exp_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

int crabc_x86_64_math_exp_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < EXP_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (input_index = 0; input_index < EXP_F64_CASES && status == 0;
			input_index++)
			status = record_binary64(&cursor, rounding_modes[mode_index],
				binary64_inputs[input_index]);
		for (input_index = 0; input_index < EXP_F32_CASES && status == 0;
			input_index++)
			status = record_binary32(&cursor, rounding_modes[mode_index],
				binary32_inputs[input_index]);
	}
	if (cursor != EXP_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_EXP_FREESTANDING
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
	int status = crabc_x86_64_math_exp_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_exp_records,
		sizeof(crabc_x86_64_math_exp_records));
}
#endif
