/*
 * Static Linux/x86-64 GNU sincos/sincosf C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive. It records both pointed-to result bits and IEEE exception
 * flags under each MXCSR rounding direction, including tiny/subnormal inputs,
 * all argument-reduction paths, signed zero, infinite, quiet-NaN, and
 * signaling-NaN inputs. A second record for every call aliases the two output
 * pointers, retaining musl's source-ordered final-store behavior. It selects
 * only binary64/binary32 GNU sincos: sincosl, public sin/cos, fenv policy,
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
#ifndef CRABC_MATH_SINCOS_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#define SINCOS_F64_CASES 32
#define SINCOS_F32_CASES 32
#define SINCOS_ROUNDING_CASES 4
#define SINCOS_RECORDS_PER_CALL 2
#define SINCOS_RECORD_WORDS 5
#define SINCOS_RECORD_COUNT \
	((SINCOS_F64_CASES + SINCOS_F32_CASES) * SINCOS_ROUNDING_CASES * \
	 SINCOS_RECORDS_PER_CALL)
#define SINCOS_RECORD_STORAGE_WORDS (SINCOS_RECORD_COUNT * SINCOS_RECORD_WORDS)
#define SINCOS_F64_ALIAS_TAG UINT64_C(0x53494e434f53414c)
#define SINCOS_F32_ALIAS_TAG UINT64_C(0x53494e434f534146)

typedef void (*double_sincos_function)(double, double *, double *);
typedef void (*float_sincos_function)(float, float *, float *);

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_sincos_function volatile direct_sincos = (sincos);
static float_sincos_function volatile direct_sincosf = (sincosf);

/* The freestanding start object writes these exact 20,480 bytes with syscall. */
uint64_t crabc_x86_64_math_sincos_records[SINCOS_RECORD_STORAGE_WORDS];

static const uint64_t binary64_inputs[SINCOS_F64_CASES] = {
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

static const uint32_t binary32_inputs[SINCOS_F32_CASES] = {
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

static const int rounding_modes[SINCOS_ROUNDING_CASES] = {
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

static void append_record(size_t *cursor, uint64_t input, uint64_t sine,
	uint64_t cosine_or_tag, int rounding_mode)
{
	crabc_x86_64_math_sincos_records[(*cursor)++] = input;
	crabc_x86_64_math_sincos_records[(*cursor)++] = sine;
	crabc_x86_64_math_sincos_records[(*cursor)++] = cosine_or_tag;
	crabc_x86_64_math_sincos_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_sincos_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
}

static int record_binary64(size_t *cursor, int rounding_mode, uint64_t input)
{
	double sine;
	double cosine;
	double aliased;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	direct_sincos(double_from_bits(input), &sine, &cosine);
	if (*cursor + SINCOS_RECORD_WORDS > SINCOS_RECORD_STORAGE_WORDS)
		return 2;
	append_record(cursor, input, double_bits(sine), double_bits(cosine),
		rounding_mode);

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	direct_sincos(double_from_bits(input), &aliased, &aliased);
	if (*cursor + SINCOS_RECORD_WORDS > SINCOS_RECORD_STORAGE_WORDS)
		return 2;
	append_record(cursor, input, double_bits(aliased), SINCOS_F64_ALIAS_TAG,
		rounding_mode);
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode, uint32_t input)
{
	float sine;
	float cosine;
	float aliased;
	uint64_t tagged_input = UINT64_C(0x0000000100000000) | input;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	direct_sincosf(float_from_bits(input), &sine, &cosine);
	if (*cursor + SINCOS_RECORD_WORDS > SINCOS_RECORD_STORAGE_WORDS)
		return 2;
	append_record(cursor, tagged_input, float_bits(sine), float_bits(cosine),
		rounding_mode);

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	direct_sincosf(float_from_bits(input), &aliased, &aliased);
	if (*cursor + SINCOS_RECORD_WORDS > SINCOS_RECORD_STORAGE_WORDS)
		return 2;
	append_record(cursor, tagged_input, float_bits(aliased), SINCOS_F32_ALIAS_TAG,
		rounding_mode);
	return 0;
}

int crabc_x86_64_math_sincos_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < SINCOS_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (input_index = 0; input_index < SINCOS_F64_CASES && status == 0;
			input_index++)
			status = record_binary64(&cursor, rounding_modes[mode_index],
				binary64_inputs[input_index]);
		for (input_index = 0; input_index < SINCOS_F32_CASES && status == 0;
			input_index++)
			status = record_binary32(&cursor, rounding_modes[mode_index],
				binary32_inputs[input_index]);
	}
	if (cursor != SINCOS_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_SINCOS_FREESTANDING
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
	int status = crabc_x86_64_math_sincos_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_sincos_records,
		sizeof(crabc_x86_64_math_sincos_records));
}
#endif
