/*
 * Static Linux/x86-64 cbrt/cbrtf C ABI differential regression.
 *
 * This fixed raw-bit corpus is executed through pinned musl 1.2.6 and then
 * through one freestanding crabc archive.  It records the result and MXCSR
 * exception flags for every input under all four rounding directions, so the
 * runner compares the two complete observable records rather than relying on
 * host libm or a handful of hand-copied expected values.  Each record retains
 * both the requested and observed rounding direction, so the candidate cannot
 * merely preserve an unrelated default MXCSR setting. It selects only the
 * binary64/binary32 cube-root pair; cbrtl, fma, complex, special, rounding,
 * and general libm are outside this artifact.
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
#ifndef CRABC_MATH_CBRT_FREESTANDING
#include <unistd.h>
#endif

#define CBRT_F64_CASES 21
#define CBRT_F32_CASES 21
#define CBRT_ROUNDING_CASES 4
#define CBRT_RECORD_WORDS 4
#define CBRT_RECORD_COUNT \
	((CBRT_F64_CASES + CBRT_F32_CASES) * CBRT_ROUNDING_CASES)
#define CBRT_RECORD_STORAGE_WORDS \
	(CBRT_RECORD_COUNT * CBRT_RECORD_WORDS)

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_unary_function volatile direct_cbrt = (cbrt);
static float_unary_function volatile direct_cbrtf = (cbrtf);

/* The freestanding start object writes these exact 5,376 bytes with syscall. */
uint64_t crabc_x86_64_math_cbrt_records[CBRT_RECORD_STORAGE_WORDS];

static const uint64_t binary64_inputs[CBRT_F64_CASES] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x000fffffffffffff),
	UINT64_C(0x0010000000000000), UINT64_C(0x8010000000000000),
	UINT64_C(0x3fc0000000000000), UINT64_C(0xbfc0000000000000),
	UINT64_C(0x3ff0000000000000), UINT64_C(0xbff0000000000000),
	UINT64_C(0x4000000000000000), UINT64_C(0xc000000000000000),
	UINT64_C(0x4020000000000000), UINT64_C(0xc020000000000000),
	UINT64_C(0x403b000000000000), UINT64_C(0xc03b000000000000),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0xffefffffffffffff),
	UINT64_C(0x7ff0000000000000), UINT64_C(0x7ff8000000000041),
	UINT64_C(0x7ff0000000000042),
};

static const uint32_t binary32_inputs[CBRT_F32_CASES] = {
	UINT32_C(0x00000000), UINT32_C(0x80000000), UINT32_C(0x00000001),
	UINT32_C(0x007fffff), UINT32_C(0x00800000), UINT32_C(0x80800000),
	UINT32_C(0x3e000000), UINT32_C(0xbe000000), UINT32_C(0x3f800000),
	UINT32_C(0xbf800000), UINT32_C(0x40000000), UINT32_C(0xc0000000),
	UINT32_C(0x41000000), UINT32_C(0xc1000000), UINT32_C(0x41d80000),
	UINT32_C(0xc1d80000), UINT32_C(0x7f7fffff), UINT32_C(0xff7fffff),
	UINT32_C(0x7f800000), UINT32_C(0x7fc00041), UINT32_C(0x7f800042),
};

static const int rounding_modes[CBRT_ROUNDING_CASES] = {
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
	result = direct_cbrt(double_from_bits(input));
	if (*cursor + CBRT_RECORD_WORDS > CBRT_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_cbrt_records[(*cursor)++] = input;
	crabc_x86_64_math_cbrt_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_cbrt_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_cbrt_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode, uint32_t input)
{
	float result;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	result = direct_cbrtf(float_from_bits(input));
	if (*cursor + CBRT_RECORD_WORDS > CBRT_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_cbrt_records[(*cursor)++] =
		UINT64_C(0x0000000100000000) | input;
	crabc_x86_64_math_cbrt_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_cbrt_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_cbrt_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return 0;
}

int crabc_x86_64_math_cbrt_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < CBRT_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (input_index = 0; input_index < CBRT_F64_CASES && status == 0;
			input_index++)
			status = record_binary64(&cursor, rounding_modes[mode_index],
				binary64_inputs[input_index]);
		for (input_index = 0; input_index < CBRT_F32_CASES && status == 0;
			input_index++)
			status = record_binary32(&cursor, rounding_modes[mode_index],
				binary32_inputs[input_index]);
	}
	if (cursor != CBRT_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_CBRT_FREESTANDING
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
	int status = crabc_x86_64_math_cbrt_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_cbrt_records,
		sizeof(crabc_x86_64_math_cbrt_records));
}
#endif
