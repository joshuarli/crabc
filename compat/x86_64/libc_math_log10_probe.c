/*
 * Static Linux/x86-64 log10/log10f C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive. It records result bits and IEEE exception flags under each
 * MXCSR rounding direction, including adjacent representable values around
 * decimal powers and source reduction boundaries, raw subnormal scaling,
 * signed-zero divide-by-zero, negative-domain invalid, infinite, quiet-NaN,
 * and signaling-NaN inputs. It selects only the binary64/binary32 base-ten
 * logarithm pair: `log10l`, fenv policy/APIs, special math, and general libm
 * remain outside this leaf.
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
#ifndef CRABC_MATH_LOG10_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#define LOG10_F64_CASES 28
#define LOG10_F32_CASES 28
#define LOG10_F64_POWERS 34
#define LOG10_F32_POWERS 22
#define LOG10_THRESHOLDS 4
#define LOG10_POWER_RADIUS 1
#define LOG10_THRESHOLD_RADIUS 16
#define LOG10_ROUNDING_CASES 4
#define LOG10_RECORD_WORDS 4
#define LOG10_RECORD_COUNT \
	((LOG10_F64_CASES + LOG10_F32_CASES + \
	  (LOG10_F64_POWERS + LOG10_F32_POWERS) * \
	    (2 * LOG10_POWER_RADIUS + 1) + \
	  2 * LOG10_THRESHOLDS * (2 * LOG10_THRESHOLD_RADIUS + 1)) * \
	 LOG10_ROUNDING_CASES)
#define LOG10_RECORD_STORAGE_WORDS (LOG10_RECORD_COUNT * LOG10_RECORD_WORDS)

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_unary_function volatile direct_log10 = (log10);
static float_unary_function volatile direct_log10f = (log10f);

/* The freestanding start object reads this byte length before writing. */
uint64_t crabc_x86_64_math_log10_records[LOG10_RECORD_STORAGE_WORDS];
const size_t crabc_x86_64_math_log10_record_bytes =
	sizeof(crabc_x86_64_math_log10_records);

static const uint64_t binary64_inputs[LOG10_F64_CASES] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x000fffffffffffff),
	UINT64_C(0x0010000000000000), UINT64_C(0x3fe6a09dffffffff),
	UINT64_C(0x3fe6a09e00000000), UINT64_C(0x3fe6a09effffffff),
	UINT64_C(0x3fe0000000000000), UINT64_C(0x3fe8000000000000),
	UINT64_C(0x3fefffffffffffff), UINT64_C(0x3ff0000000000000),
	UINT64_C(0x3ff0000000000001), UINT64_C(0x3ff8000000000000),
	UINT64_C(0x3ff6a09e667f3bcd), UINT64_C(0x4000000000000000),
	UINT64_C(0x4024000000000000), UINT64_C(0x4059000000000000),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0x7ff0000000000000),
	UINT64_C(0x7ff8000000000041), UINT64_C(0x7ff0000000000042),
	UINT64_C(0x8000000000000001), UINT64_C(0x8010000000000000),
	UINT64_C(0xbfe0000000000000), UINT64_C(0xbff0000000000000),
	UINT64_C(0xffefffffffffffff), UINT64_C(0xfff0000000000000),
};

static const uint32_t binary32_inputs[LOG10_F32_CASES] = {
	UINT32_C(0x00000000), UINT32_C(0x80000000), UINT32_C(0x00000001),
	UINT32_C(0x007fffff), UINT32_C(0x00800000), UINT32_C(0x3f3504f2),
	UINT32_C(0x3f3504f3), UINT32_C(0x3f3504f4), UINT32_C(0x3f000000),
	UINT32_C(0x3f400000), UINT32_C(0x3f7fffff), UINT32_C(0x3f800000),
	UINT32_C(0x3f800001), UINT32_C(0x3fc00000), UINT32_C(0x3fb504f3),
	UINT32_C(0x40000000), UINT32_C(0x41200000), UINT32_C(0x42c80000),
	UINT32_C(0x7f7fffff), UINT32_C(0x7f800000), UINT32_C(0x7fc00041),
	UINT32_C(0x7f800042), UINT32_C(0x80000001), UINT32_C(0x80800000),
	UINT32_C(0xbf000000), UINT32_C(0xbf800000), UINT32_C(0xff7fffff),
	UINT32_C(0xff800000),
};

/* Binary64 encodings of 10^e, including the subnormal and finite extremes. */
static const uint64_t binary64_powers[LOG10_F64_POWERS] = {
	UINT64_C(0x0000000000000002), /* 10^-323 */
	UINT64_C(0x00000000000007e8), /* 10^-320 */
	UINT64_C(0x000012688b70e62b), /* 10^-310 */
	UINT64_C(0x000730d67819e8d2), /* 10^-308 */
	UINT64_C(0x0031fa182c40c60d), /* 10^-307 */
	UINT64_C(0x01a56e1fc2f8f359), /* 10^-300 */
	UINT64_C(0x05cd0b15a491eb84), /* 10^-280 */
	UINT64_C(0x0c06e93f5da2824c), /* 10^-250 */
	UINT64_C(0x16687e92154ef7ac), /* 10^-200 */
	UINT64_C(0x20ca2fe76a3f9475), /* 10^-150 */
	UINT64_C(0x2b2bff2ee48e0530), /* 10^-100 */
	UINT64_C(0x358dee7a4ad4b81f), /* 10^-50 */
	UINT64_C(0x3bc79ca10c924223), /* 10^-20 */
	UINT64_C(0x3ddb7cdfd9d7bdbb), /* 10^-10 */
	UINT64_C(0x3ee4f8b588e368f1), /* 10^-5 */
	UINT64_C(0x3f50624dd2f1a9fc), /* 10^-3 */
	UINT64_C(0x3f847ae147ae147b), /* 10^-2 */
	UINT64_C(0x3fb999999999999a), /* 10^-1 */
	UINT64_C(0x3ff0000000000000), /* 10^0 */
	UINT64_C(0x4024000000000000), /* 10^1 */
	UINT64_C(0x4059000000000000), /* 10^2 */
	UINT64_C(0x408f400000000000), /* 10^3 */
	UINT64_C(0x40f86a0000000000), /* 10^5 */
	UINT64_C(0x4202a05f20000000), /* 10^10 */
	UINT64_C(0x4415af1d78b58c40), /* 10^20 */
	UINT64_C(0x4a511b0ec57e649a), /* 10^50 */
	UINT64_C(0x54b249ad2594c37d), /* 10^100 */
	UINT64_C(0x5f138d352e5096af), /* 10^150 */
	UINT64_C(0x6974e718d7d7625a), /* 10^200 */
	UINT64_C(0x73d658e3ab795204), /* 10^250 */
	UINT64_C(0x7a11a0fc668aac70), /* 10^280 */
	UINT64_C(0x7e37e43c8800759c), /* 10^300 */
	UINT64_C(0x7fac7b1f3cac7433), /* 10^307 */
	UINT64_C(0x7fe1ccf385ebc8a0), /* 10^308 */
};

/* Binary32 encodings of 10^e, including the subnormal and finite extremes. */
static const uint32_t binary32_powers[LOG10_F32_POWERS] = {
	UINT32_C(0x00000001), /* 10^-45 */
	UINT32_C(0x00000007), /* 10^-44 */
	UINT32_C(0x000116c2), /* 10^-40 */
	UINT32_C(0x006ce3ee), /* 10^-38 */
	UINT32_C(0x02081cea), /* 10^-37 */
	UINT32_C(0x0da24260), /* 10^-30 */
	UINT32_C(0x1e3ce508), /* 10^-20 */
	UINT32_C(0x2edbe6ff), /* 10^-10 */
	UINT32_C(0x3727c5ac), /* 10^-5 */
	UINT32_C(0x3a83126f), /* 10^-3 */
	UINT32_C(0x3c23d70a), /* 10^-2 */
	UINT32_C(0x3dcccccd), /* 10^-1 */
	UINT32_C(0x3f800000), /* 10^0 */
	UINT32_C(0x41200000), /* 10^1 */
	UINT32_C(0x42c80000), /* 10^2 */
	UINT32_C(0x447a0000), /* 10^3 */
	UINT32_C(0x47c35000), /* 10^5 */
	UINT32_C(0x501502f9), /* 10^10 */
	UINT32_C(0x60ad78ec), /* 10^20 */
	UINT32_C(0x7149f2ca), /* 10^30 */
	UINT32_C(0x7cf0bdc2), /* 10^37 */
	UINT32_C(0x7e967699), /* 10^38 */
};

/* Reduction crossover, normal/subnormal boundary, and cancellation at one. */
static const uint64_t binary64_thresholds[LOG10_THRESHOLDS] = {
	UINT64_C(0x000fffffffffffff), UINT64_C(0x0010000000000000),
	UINT64_C(0x3fe6a09e00000000), UINT64_C(0x3ff0000000000000),
};
static const uint32_t binary32_thresholds[LOG10_THRESHOLDS] = {
	UINT32_C(0x007fffff), UINT32_C(0x00800000),
	UINT32_C(0x3f3504f3), UINT32_C(0x3f800000),
};

static const int rounding_modes[LOG10_ROUNDING_CASES] = {
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
	result = direct_log10(double_from_bits(input));
	if (*cursor + LOG10_RECORD_WORDS > LOG10_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_log10_records[(*cursor)++] = input;
	crabc_x86_64_math_log10_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_log10_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_log10_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode, uint32_t input)
{
	float result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	result = direct_log10f(float_from_bits(input));
	if (*cursor + LOG10_RECORD_WORDS > LOG10_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_log10_records[(*cursor)++] =
		UINT64_C(0x0000000100000000) | input;
	crabc_x86_64_math_log10_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_log10_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_log10_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

static int record_binary64_neighbors(size_t *cursor, int rounding_mode,
	uint64_t center, uint64_t radius)
{
	uint64_t bits;
	int status;

	for (bits = center - radius; bits <= center + radius; bits++) {
		status = record_binary64(cursor, rounding_mode, bits);
		if (status != 0)
			return status;
	}
	return 0;
}

static int record_binary32_neighbors(size_t *cursor, int rounding_mode,
	uint32_t center, uint32_t radius)
{
	uint32_t bits;
	int status;

	for (bits = center - radius; bits <= center + radius; bits++) {
		status = record_binary32(cursor, rounding_mode, bits);
		if (status != 0)
			return status;
	}
	return 0;
}

int crabc_x86_64_math_log10_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < LOG10_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (input_index = 0; input_index < LOG10_F64_CASES && status == 0;
			input_index++)
			status = record_binary64(&cursor, rounding_modes[mode_index],
				binary64_inputs[input_index]);
		for (input_index = 0; input_index < LOG10_F32_CASES && status == 0;
			input_index++)
			status = record_binary32(&cursor, rounding_modes[mode_index],
				binary32_inputs[input_index]);
		for (input_index = 0; input_index < LOG10_F64_POWERS && status == 0;
			input_index++)
			status = record_binary64_neighbors(&cursor,
				rounding_modes[mode_index], binary64_powers[input_index],
				LOG10_POWER_RADIUS);
		for (input_index = 0; input_index < LOG10_F32_POWERS && status == 0;
			input_index++)
			status = record_binary32_neighbors(&cursor,
				rounding_modes[mode_index], binary32_powers[input_index],
				LOG10_POWER_RADIUS);
		for (input_index = 0; input_index < LOG10_THRESHOLDS && status == 0;
			input_index++)
			status = record_binary64_neighbors(&cursor,
				rounding_modes[mode_index], binary64_thresholds[input_index],
				LOG10_THRESHOLD_RADIUS);
		for (input_index = 0; input_index < LOG10_THRESHOLDS && status == 0;
			input_index++)
			status = record_binary32_neighbors(&cursor,
				rounding_modes[mode_index], binary32_thresholds[input_index],
				LOG10_THRESHOLD_RADIUS);
	}
	if (cursor != LOG10_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_LOG10_FREESTANDING
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
	int status = crabc_x86_64_math_log10_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_log10_records,
		sizeof(crabc_x86_64_math_log10_records));
}
#endif
