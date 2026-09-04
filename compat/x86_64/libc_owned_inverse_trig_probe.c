/*
 * Installed and freestanding Linux/x86-64 owned inverse-trigonometry probe.
 *
 * Pinned musl 1.2.6 and the candidate record raw result bits, rounding mode,
 * IEEE flags, and (for the installed CRT/TLS execution) errno for all eight
 * binary32/binary64 asin, acos, atan, and atan2 entries. The corpus covers
 * signed zero, normal/subnormal boundaries, source argument-reduction edges,
 * asin/acos domains, infinities, quiet/signaling NaNs, and atan2 quadrants
 * and extreme ratios. Parenthesized volatile function pointers prohibit a
 * compiler builtin or an ambient libm from replacing the target ABI call.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#ifndef CRABC_OWNED_INVERSE_TRIG_FREESTANDING
#include <errno.h>
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#if FLT_EVAL_METHOD != 0
#error "the raw binary32/binary64 fixture requires SSE evaluation"
#endif

#define ARRAY_COUNT(array) (sizeof(array) / sizeof((array)[0]))
#define ROUNDING_CASES 4
#define RECORD_WORDS 6
#define ERRNO_SENTINEL 0x5a

enum function_id {
	ID_ASIN = 1,
	ID_ACOS,
	ID_ATAN,
	ID_ATAN2,
	ID_ASINF,
	ID_ACOSF,
	ID_ATANF,
	ID_ATAN2F,
};

typedef double (*double_unary_function)(double);
typedef double (*double_binary_function)(double, double);
typedef float (*float_unary_function)(float);
typedef float (*float_binary_function)(float, float);

struct binary64_case { uint64_t y; uint64_t x; };
struct binary32_case { uint32_t y; uint32_t x; };

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_unary_function volatile direct_asin = (asin);
static double_unary_function volatile direct_acos = (acos);
static double_unary_function volatile direct_atan = (atan);
static double_binary_function volatile direct_atan2 = (atan2);
static float_unary_function volatile direct_asinf = (asinf);
static float_unary_function volatile direct_acosf = (acosf);
static float_unary_function volatile direct_atanf = (atanf);
static float_binary_function volatile direct_atan2f = (atan2f);

static const uint64_t binary64_unary_inputs[] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x8000000000000001),
	UINT64_C(0x000fffffffffffff), UINT64_C(0x800fffffffffffff),
	UINT64_C(0x0010000000000000), UINT64_C(0x8010000000000000),
	UINT64_C(0x3fdbffffffffffff), UINT64_C(0x3fdc000000000000),
	UINT64_C(0x3fdc000000000001), UINT64_C(0xbfdc000000000000),
	UINT64_C(0x3fe0000000000000), UINT64_C(0xbfe0000000000000),
	UINT64_C(0x3fe5ffffffffffff), UINT64_C(0x3fe6000000000000),
	UINT64_C(0x3ff2ffffffffffff), UINT64_C(0x3ff3000000000000),
	UINT64_C(0x3fef3332ffffffff), UINT64_C(0x3fef333300000000),
	UINT64_C(0x3fef333300000001), UINT64_C(0xbfefffffffffffff),
	UINT64_C(0x3ff0000000000000), UINT64_C(0xbff0000000000000),
	UINT64_C(0x3ff0000000000001), UINT64_C(0xbff0000000000001),
	UINT64_C(0x40037fffffffffff), UINT64_C(0x4003800000000000),
	UINT64_C(0x440fffffffffffff), UINT64_C(0x4410000000000000),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0xffefffffffffffff),
	UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
	UINT64_C(0x7ff8000000000041), UINT64_C(0xfff8000000000041),
	UINT64_C(0x7ff0000000000042), UINT64_C(0xfff0000000000042),
};

static const uint32_t binary32_unary_inputs[] = {
	UINT32_C(0x00000000), UINT32_C(0x80000000),
	UINT32_C(0x00000001), UINT32_C(0x80000001),
	UINT32_C(0x007fffff), UINT32_C(0x807fffff),
	UINT32_C(0x00800000), UINT32_C(0x80800000),
	UINT32_C(0x3edfffff), UINT32_C(0x3ee00000),
	UINT32_C(0x3ee00001), UINT32_C(0xbee00000),
	UINT32_C(0x3f000000), UINT32_C(0xbf000000),
	UINT32_C(0x3f2fffff), UINT32_C(0x3f300000),
	UINT32_C(0x3f97ffff), UINT32_C(0x3f980000),
	UINT32_C(0x401bffff), UINT32_C(0x401c0000),
	UINT32_C(0x3f799999), UINT32_C(0x3f79999a),
	UINT32_C(0x3f79999b), UINT32_C(0xbf7fffff),
	UINT32_C(0x3f800000), UINT32_C(0xbf800000),
	UINT32_C(0x3f800001), UINT32_C(0xbf800001),
	UINT32_C(0x4c7fffff), UINT32_C(0x4c800000),
	UINT32_C(0x7f7fffff), UINT32_C(0xff7fffff),
	UINT32_C(0x7f800000), UINT32_C(0xff800000),
	UINT32_C(0x7fc00041), UINT32_C(0xffc00041),
	UINT32_C(0x7f800042), UINT32_C(0xff800042),
};

static const struct binary64_case binary64_atan2_inputs[] = {
	{ UINT64_C(0x0000000000000000), UINT64_C(0x3ff0000000000000) },
	{ UINT64_C(0x8000000000000000), UINT64_C(0x3ff0000000000000) },
	{ UINT64_C(0x0000000000000000), UINT64_C(0xbff0000000000000) },
	{ UINT64_C(0x8000000000000000), UINT64_C(0xbff0000000000000) },
	{ UINT64_C(0x3ff0000000000000), UINT64_C(0x0000000000000000) },
	{ UINT64_C(0xbff0000000000000), UINT64_C(0x0000000000000000) },
	{ UINT64_C(0x3ff0000000000000), UINT64_C(0x8000000000000000) },
	{ UINT64_C(0xbff0000000000000), UINT64_C(0x8000000000000000) },
	{ UINT64_C(0x3ff0000000000000), UINT64_C(0x3ff0000000000000) },
	{ UINT64_C(0xbff0000000000000), UINT64_C(0x3ff0000000000000) },
	{ UINT64_C(0x3ff0000000000000), UINT64_C(0xbff0000000000000) },
	{ UINT64_C(0xbff0000000000000), UINT64_C(0xbff0000000000000) },
	{ UINT64_C(0x7ff0000000000000), UINT64_C(0x7ff0000000000000) },
	{ UINT64_C(0xfff0000000000000), UINT64_C(0x7ff0000000000000) },
	{ UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000) },
	{ UINT64_C(0xfff0000000000000), UINT64_C(0xfff0000000000000) },
	{ UINT64_C(0x3ff0000000000000), UINT64_C(0x7ff0000000000000) },
	{ UINT64_C(0x8000000000000001), UINT64_C(0x7ff0000000000000) },
	{ UINT64_C(0x3ff0000000000000), UINT64_C(0xfff0000000000000) },
	{ UINT64_C(0x0000000000000001), UINT64_C(0xfff0000000000000) },
	{ UINT64_C(0x7ff0000000000000), UINT64_C(0x3ff0000000000000) },
	{ UINT64_C(0xfff0000000000000), UINT64_C(0xbff0000000000000) },
	{ UINT64_C(0x0010000000000000), UINT64_C(0x7fefffffffffffff) },
	{ UINT64_C(0x7fefffffffffffff), UINT64_C(0x0010000000000000) },
	{ UINT64_C(0x0000000000000001), UINT64_C(0xc7f0000000000000) },
	{ UINT64_C(0x0000000000000001), UINT64_C(0x47f0000000000000) },
	{ UINT64_C(0x3ff8000000000000), UINT64_C(0x3ff0000000000000) },
	{ UINT64_C(0x7ff8000000000041), UINT64_C(0x3ff0000000000000) },
	{ UINT64_C(0x3ff0000000000000), UINT64_C(0x7ff8000000000041) },
	{ UINT64_C(0x7ff0000000000042), UINT64_C(0x3ff0000000000000) },
	{ UINT64_C(0x3ff0000000000000), UINT64_C(0x7ff0000000000042) },
	{ UINT64_C(0xc0000000000000), UINT64_C(0x3ff0000000000000) },
};

static const struct binary32_case binary32_atan2_inputs[] = {
	{ UINT32_C(0x00000000), UINT32_C(0x3f800000) },
	{ UINT32_C(0x80000000), UINT32_C(0x3f800000) },
	{ UINT32_C(0x00000000), UINT32_C(0xbf800000) },
	{ UINT32_C(0x80000000), UINT32_C(0xbf800000) },
	{ UINT32_C(0x3f800000), UINT32_C(0x00000000) },
	{ UINT32_C(0xbf800000), UINT32_C(0x00000000) },
	{ UINT32_C(0x3f800000), UINT32_C(0x80000000) },
	{ UINT32_C(0xbf800000), UINT32_C(0x80000000) },
	{ UINT32_C(0x3f800000), UINT32_C(0x3f800000) },
	{ UINT32_C(0xbf800000), UINT32_C(0x3f800000) },
	{ UINT32_C(0x3f800000), UINT32_C(0xbf800000) },
	{ UINT32_C(0xbf800000), UINT32_C(0xbf800000) },
	{ UINT32_C(0x7f800000), UINT32_C(0x7f800000) },
	{ UINT32_C(0xff800000), UINT32_C(0x7f800000) },
	{ UINT32_C(0x7f800000), UINT32_C(0xff800000) },
	{ UINT32_C(0xff800000), UINT32_C(0xff800000) },
	{ UINT32_C(0x3f800000), UINT32_C(0x7f800000) },
	{ UINT32_C(0x80000001), UINT32_C(0x7f800000) },
	{ UINT32_C(0x3f800000), UINT32_C(0xff800000) },
	{ UINT32_C(0x00000001), UINT32_C(0xff800000) },
	{ UINT32_C(0x7f800000), UINT32_C(0x3f800000) },
	{ UINT32_C(0xff800000), UINT32_C(0xbf800000) },
	{ UINT32_C(0x00800000), UINT32_C(0x7f7fffff) },
	{ UINT32_C(0x7f7fffff), UINT32_C(0x00800000) },
	{ UINT32_C(0x00000001), UINT32_C(0xcb800000) },
	{ UINT32_C(0x00000001), UINT32_C(0x4b800000) },
	{ UINT32_C(0x3fc00000), UINT32_C(0x3f800000) },
	{ UINT32_C(0x7fc00041), UINT32_C(0x3f800000) },
	{ UINT32_C(0x3f800000), UINT32_C(0x7fc00041) },
	{ UINT32_C(0x7f800042), UINT32_C(0x3f800000) },
	{ UINT32_C(0x3f800000), UINT32_C(0x7f800042) },
	{ UINT32_C(0xc0000000), UINT32_C(0x3f800000) },
};

static const int rounding_modes[ROUNDING_CASES] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

#define RECORD_COUNT ((3 * ARRAY_COUNT(binary64_unary_inputs) + \
	ARRAY_COUNT(binary64_atan2_inputs) + 3 * ARRAY_COUNT(binary32_unary_inputs) + \
	ARRAY_COUNT(binary32_atan2_inputs)) * ROUNDING_CASES)
#define RECORD_STORAGE_WORDS (RECORD_COUNT * RECORD_WORDS)

uint64_t crabc_x86_64_owned_inverse_trig_records[RECORD_STORAGE_WORDS];
const size_t crabc_x86_64_owned_inverse_trig_records_bytes =
	sizeof(crabc_x86_64_owned_inverse_trig_records);

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

static void set_errno_sentinel(void)
{
#ifndef CRABC_OWNED_INVERSE_TRIG_FREESTANDING
	errno = ERRNO_SENTINEL;
#endif
}

static unsigned int observed_errno(void)
{
#ifndef CRABC_OWNED_INVERSE_TRIG_FREESTANDING
	return (unsigned int)errno;
#else
	return 0;
#endif
}

static int begin_case(int rounding_mode)
{
	return fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0;
}

static int emit_record(size_t *cursor, unsigned int function, uint64_t first,
	uint64_t second, uint64_t result, int rounding_mode)
{
	if (*cursor + RECORD_WORDS > RECORD_STORAGE_WORDS)
		return 1;
	crabc_x86_64_owned_inverse_trig_records[(*cursor)++] = function;
	crabc_x86_64_owned_inverse_trig_records[(*cursor)++] = first;
	crabc_x86_64_owned_inverse_trig_records[(*cursor)++] = second;
	crabc_x86_64_owned_inverse_trig_records[(*cursor)++] = result;
	crabc_x86_64_owned_inverse_trig_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) | (uint32_t)fegetround();
	crabc_x86_64_owned_inverse_trig_records[(*cursor)++] =
		((uint64_t)observed_errno() << 32) |
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

static int record_double_unary(size_t *cursor, unsigned int function,
	double_unary_function entry, int rounding_mode, uint64_t input)
{
	double result;
	if (begin_case(rounding_mode)) return 1;
	set_errno_sentinel();
	result = entry(double_from_bits(input));
	return emit_record(cursor, function, input, 0, double_bits(result), rounding_mode);
}

static int record_float_unary(size_t *cursor, unsigned int function,
	float_unary_function entry, int rounding_mode, uint32_t input)
{
	float result;
	if (begin_case(rounding_mode)) return 1;
	set_errno_sentinel();
	result = entry(float_from_bits(input));
	return emit_record(cursor, function, input, 0, float_bits(result), rounding_mode);
}

static int record_double_binary(size_t *cursor, int rounding_mode,
	const struct binary64_case *test_case)
{
	double result;
	if (begin_case(rounding_mode)) return 1;
	set_errno_sentinel();
	result = direct_atan2(double_from_bits(test_case->y), double_from_bits(test_case->x));
	return emit_record(cursor, ID_ATAN2, test_case->y, test_case->x,
		double_bits(result), rounding_mode);
}

static int record_float_binary(size_t *cursor, int rounding_mode,
	const struct binary32_case *test_case)
{
	float result;
	if (begin_case(rounding_mode)) return 1;
	set_errno_sentinel();
	result = direct_atan2f(float_from_bits(test_case->y), float_from_bits(test_case->x));
	return emit_record(cursor, ID_ATAN2F, test_case->y, test_case->x,
		float_bits(result), rounding_mode);
}

int crabc_x86_64_owned_inverse_trig_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < ROUNDING_CASES && status == 0; mode_index++) {
		int mode = rounding_modes[mode_index];
		for (index = 0; index < ARRAY_COUNT(binary64_unary_inputs) && status == 0; index++)
			status = record_double_unary(&cursor, ID_ASIN, direct_asin, mode, binary64_unary_inputs[index]);
		for (index = 0; index < ARRAY_COUNT(binary64_unary_inputs) && status == 0; index++)
			status = record_double_unary(&cursor, ID_ACOS, direct_acos, mode, binary64_unary_inputs[index]);
		for (index = 0; index < ARRAY_COUNT(binary64_unary_inputs) && status == 0; index++)
			status = record_double_unary(&cursor, ID_ATAN, direct_atan, mode, binary64_unary_inputs[index]);
		for (index = 0; index < ARRAY_COUNT(binary64_atan2_inputs) && status == 0; index++)
			status = record_double_binary(&cursor, mode, &binary64_atan2_inputs[index]);
		for (index = 0; index < ARRAY_COUNT(binary32_unary_inputs) && status == 0; index++)
			status = record_float_unary(&cursor, ID_ASINF, direct_asinf, mode, binary32_unary_inputs[index]);
		for (index = 0; index < ARRAY_COUNT(binary32_unary_inputs) && status == 0; index++)
			status = record_float_unary(&cursor, ID_ACOSF, direct_acosf, mode, binary32_unary_inputs[index]);
		for (index = 0; index < ARRAY_COUNT(binary32_unary_inputs) && status == 0; index++)
			status = record_float_unary(&cursor, ID_ATANF, direct_atanf, mode, binary32_unary_inputs[index]);
		for (index = 0; index < ARRAY_COUNT(binary32_atan2_inputs) && status == 0; index++)
			status = record_float_binary(&cursor, mode, &binary32_atan2_inputs[index]);
	}
	if (cursor != RECORD_STORAGE_WORDS && status == 0)
		status = 2;
	if (fesetenv(&original) != 0 && status == 0)
		status = 3;
	return status;
}

#ifndef CRABC_OWNED_INVERSE_TRIG_FREESTANDING
static int write_all(const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;
	while (length != 0) {
		ssize_t written = write(1, cursor, length);
		if (written <= 0) return 1;
		cursor += written;
		length -= (size_t)written;
	}
	return 0;
}

int main(void)
{
	int status = crabc_x86_64_owned_inverse_trig_probe();
	if (status != 0) return status;
	return write_all(crabc_x86_64_owned_inverse_trig_records,
		sizeof(crabc_x86_64_owned_inverse_trig_records));
}
#endif
