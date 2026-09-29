/*
 * Static Linux/x86-64 tan/tanf C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive. It records result bits and IEEE exception flags under each
 * MXCSR rounding direction, including tiny/subnormal inputs, all argument
 * reduction paths, signed zero, infinite, quiet-NaN, and signaling-NaN
 * inputs. Each record also preserves MXCSR before and after the call. It
 * selects only binary64/binary32 tangent: tanl, sincos, fenv policy,
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
#ifndef CRABC_MATH_TAN_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#define TAN_F64_BASE_CASES 32
#define TAN_F32_BASE_CASES 32
#define TAN_ROUNDING_CASES 4
#define TAN_RECORD_WORDS 5
#define ARRAY_COUNT(values) (sizeof(values) / sizeof((values)[0]))

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_unary_function volatile direct_tan = (tan);
static float_unary_function volatile direct_tanf = (tanf);

static const uint64_t binary64_inputs[TAN_F64_BASE_CASES] = {
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

static const uint32_t binary32_inputs[TAN_F32_BASE_CASES] = {
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

/* These seeds cover small-argument cutoffs and rounded quadrant boundaries,
 * including multiples of pi/2 over a wide range of finite magnitudes. Each
 * seed is exercised at its two neighboring ulps on both sides and signs. */
static const uint64_t binary64_neighbors[] = {
	UINT64_C(0x3e40000000000000), UINT64_C(0x3e50000000000000),
	UINT64_C(0x3fe921fb54442d18), UINT64_C(0x4002d97c7f3321d2),
	UINT64_C(0x3ff921fb54442d18), UINT64_C(0x400921fb54442d18),
	UINT64_C(0x4012d97c7f3321d2), UINT64_C(0x401921fb54442d18),
	UINT64_C(0x401f6a7a2955385e), UINT64_C(0x4022d97c7f3321d2),
	UINT64_C(0x4025fdbbe9bba775), UINT64_C(0x402921fb54442d18),
	UINT64_C(0x40378fdb9effea47), UINT64_C(0x403921fb54442d18),
	UINT64_C(0x404858eb79a20bb0), UINT64_C(0x404921fb54442d18),
	UINT64_C(0x4058bd7366f31c64), UINT64_C(0x405921fb54442d18),
	UINT64_C(0x4068efb75d9ba4be), UINT64_C(0x406921fb54442d18),
	UINT64_C(0x40991bb2d56f1c0d), UINT64_C(0x409921fb54442d18),
	UINT64_C(0x40f921e23248d8d4), UINT64_C(0x40f921fb54442d18),
};

static const uint32_t binary32_neighbors[] = {
	UINT32_C(0x39800000), UINT32_C(0x3a000000),
	UINT32_C(0x3f490fdb), UINT32_C(0x4016cbe4),
	UINT32_C(0x3fc90fdb), UINT32_C(0x40490fdb),
	UINT32_C(0x4096cbe4), UINT32_C(0x40c90fdb),
	UINT32_C(0x40fb53d1), UINT32_C(0x4116cbe4),
	UINT32_C(0x412feddf), UINT32_C(0x41490fdb),
	UINT32_C(0x41bc7edd), UINT32_C(0x41c90fdb),
	UINT32_C(0x4242c75c), UINT32_C(0x42490fdb),
	UINT32_C(0x42c5eb9b), UINT32_C(0x42c90fdb),
	UINT32_C(0x43477dbb), UINT32_C(0x43490fdb),
	UINT32_C(0x44c8dd97), UINT32_C(0x44c90fdb),
	UINT32_C(0x47c90f12), UINT32_C(0x47c90fdb),
};

/* The mantissas cover exact powers, their next value, the midpoint, and the
 * largest significand at reduction scale changes. */
static const uint16_t binary64_exponents[] = {
	1, 2, 512, 996, 1022, 1023, 1024, 1043, 1075, 1200, 1536, 2046,
};
static const uint8_t binary32_exponents[] = {
	1, 2, 63, 112, 126, 127, 128, 147, 150, 200, 253, 254,
};
static const uint64_t binary64_mantissas[] = {
	UINT64_C(0), UINT64_C(1), UINT64_C(0x0008000000000000),
	UINT64_C(0x000fffffffffffff),
};
static const uint32_t binary32_mantissas[] = {
	UINT32_C(0), UINT32_C(1), UINT32_C(0x00400000),
	UINT32_C(0x007fffff),
};

enum {
	TAN_F64_CASES = TAN_F64_BASE_CASES + ARRAY_COUNT(binary64_neighbors) * 10 +
		ARRAY_COUNT(binary64_exponents) * ARRAY_COUNT(binary64_mantissas) * 2,
	TAN_F32_CASES = TAN_F32_BASE_CASES + ARRAY_COUNT(binary32_neighbors) * 10 +
		ARRAY_COUNT(binary32_exponents) * ARRAY_COUNT(binary32_mantissas) * 2,
	TAN_RECORD_COUNT = (TAN_F64_CASES + TAN_F32_CASES) * TAN_ROUNDING_CASES,
	TAN_RECORD_STORAGE_WORDS = TAN_RECORD_COUNT * TAN_RECORD_WORDS,
};

/* Each record holds tagged input bits, result bits, requested/actual rounding,
 * fenv exception flags, and pre-call/post-call MXCSR in that order. */
uint64_t crabc_x86_64_math_tan_records[TAN_RECORD_STORAGE_WORDS];
const size_t crabc_x86_64_math_tan_record_bytes =
	sizeof(crabc_x86_64_math_tan_records);

static const int rounding_modes[TAN_ROUNDING_CASES] = {
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

static uint32_t current_mxcsr(void)
{
	uint32_t value;

	__asm__ volatile ("stmxcsr %0" : "=m" (value));
	return value;
}

static int record_binary64(size_t *cursor, int rounding_mode, uint64_t input)
{
	double result;
	uint32_t before, after;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	before = current_mxcsr();
	if ((before & UINT32_C(0x6000)) != (uint32_t)(rounding_mode << 3) ||
		(before & UINT32_C(0x8040)) != 0)
		return 5;
	result = direct_tan(double_from_bits(input));
	after = current_mxcsr();
	if (*cursor + TAN_RECORD_WORDS > TAN_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_tan_records[(*cursor)++] = input;
	crabc_x86_64_math_tan_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_tan_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_tan_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	crabc_x86_64_math_tan_records[(*cursor)++] =
		((uint64_t)before << 32) | after;
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode, uint32_t input)
{
	float result;
	uint32_t before, after;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	before = current_mxcsr();
	if ((before & UINT32_C(0x6000)) != (uint32_t)(rounding_mode << 3) ||
		(before & UINT32_C(0x8040)) != 0)
		return 5;
	result = direct_tanf(float_from_bits(input));
	after = current_mxcsr();
	if (*cursor + TAN_RECORD_WORDS > TAN_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_tan_records[(*cursor)++] =
		UINT64_C(0x0000000100000000) | input;
	crabc_x86_64_math_tan_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_tan_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_tan_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	crabc_x86_64_math_tan_records[(*cursor)++] =
		((uint64_t)before << 32) | after;
	return 0;
}

static int record_binary64_cases(size_t *cursor, int rounding_mode)
{
	size_t index, mantissa_index;
	int delta, status;
	uint64_t bits;

	for (index = 0; index < ARRAY_COUNT(binary64_inputs); index++) {
		status = record_binary64(cursor, rounding_mode, binary64_inputs[index]);
		if (status != 0)
			return status;
	}
	for (index = 0; index < ARRAY_COUNT(binary64_neighbors); index++) {
		for (delta = -2; delta <= 2; delta++) {
			bits = binary64_neighbors[index] + delta;
			status = record_binary64(cursor, rounding_mode, bits);
			if (status != 0)
				return status;
			status = record_binary64(cursor, rounding_mode,
				bits | UINT64_C(0x8000000000000000));
			if (status != 0)
				return status;
		}
	}
	for (index = 0; index < ARRAY_COUNT(binary64_exponents); index++) {
		for (mantissa_index = 0;
			mantissa_index < ARRAY_COUNT(binary64_mantissas);
			mantissa_index++) {
			bits = ((uint64_t)binary64_exponents[index] << 52) |
				binary64_mantissas[mantissa_index];
			status = record_binary64(cursor, rounding_mode, bits);
			if (status != 0)
				return status;
			status = record_binary64(cursor, rounding_mode,
				bits | UINT64_C(0x8000000000000000));
			if (status != 0)
				return status;
		}
	}
	return 0;
}

static int record_binary32_cases(size_t *cursor, int rounding_mode)
{
	size_t index, mantissa_index;
	int delta, status;
	uint32_t bits;

	for (index = 0; index < ARRAY_COUNT(binary32_inputs); index++) {
		status = record_binary32(cursor, rounding_mode, binary32_inputs[index]);
		if (status != 0)
			return status;
	}
	for (index = 0; index < ARRAY_COUNT(binary32_neighbors); index++) {
		for (delta = -2; delta <= 2; delta++) {
			bits = binary32_neighbors[index] + delta;
			status = record_binary32(cursor, rounding_mode, bits);
			if (status != 0)
				return status;
			status = record_binary32(cursor, rounding_mode,
				bits | UINT32_C(0x80000000));
			if (status != 0)
				return status;
		}
	}
	for (index = 0; index < ARRAY_COUNT(binary32_exponents); index++) {
		for (mantissa_index = 0;
			mantissa_index < ARRAY_COUNT(binary32_mantissas);
			mantissa_index++) {
			bits = ((uint32_t)binary32_exponents[index] << 23) |
				binary32_mantissas[mantissa_index];
			status = record_binary32(cursor, rounding_mode, bits);
			if (status != 0)
				return status;
			status = record_binary32(cursor, rounding_mode,
				bits | UINT32_C(0x80000000));
			if (status != 0)
				return status;
		}
	}
	return 0;
}

int crabc_x86_64_math_tan_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < TAN_ROUNDING_CASES && status == 0;
		mode_index++) {
		status = record_binary64_cases(&cursor, rounding_modes[mode_index]);
		if (status == 0)
			status = record_binary32_cases(&cursor, rounding_modes[mode_index]);
	}
	if (cursor != TAN_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_TAN_FREESTANDING
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
	int status = crabc_x86_64_math_tan_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_tan_records,
		sizeof(crabc_x86_64_math_tan_records));
}
#endif
