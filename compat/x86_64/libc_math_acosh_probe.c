/*
 * Static Linux/x86-64 acosh/acoshf C ABI differential regression.
 *
 * This raw-bit corpus runs through pinned musl 1.2.6 and one freestanding
 * crabc archive. It records result bits and IEEE exception flags under each
 * MXCSR rounding direction, including the source's below-one domain,
 * near-one, two, and large-input branch boundaries, signed zero, infinite,
 * quiet-NaN, and signaling-NaN inputs. Fixed neighborhoods cover both sides
 * of the branch cuts; an exponent grid exercises the reconstruction interiors.
 * It selects only binary64/binary32
 * inverse hyperbolic cosine: acoshl, fenv policy, special/complex math, and
 * general libm remain outside this leaf.
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
#ifndef CRABC_MATH_ACOSH_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

#if FLT_EVAL_METHOD != 0
#error "the raw binary32/binary64 fixture requires SSE evaluation"
#endif

#define ACOSH_BASE_CASES 32
#define ACOSH_EDGE_CASES 8
#define ACOSH_EDGE_RADIUS 16
#define ACOSH_EDGE_WIDTH (2 * ACOSH_EDGE_RADIUS + 1)
#define ACOSH_GRID_CASES 512
#define ACOSH_F64_CASES (ACOSH_BASE_CASES + 2 * ACOSH_EDGE_CASES * ACOSH_EDGE_WIDTH + ACOSH_GRID_CASES)
#define ACOSH_F32_CASES ACOSH_F64_CASES
#define ACOSH_ROUNDING_CASES 4
#define ACOSH_RECORD_WORDS 5
#define ACOSH_RECORD_COUNT ((ACOSH_F64_CASES + ACOSH_F32_CASES) * ACOSH_ROUNDING_CASES)
#define ACOSH_RECORD_STORAGE_WORDS (ACOSH_RECORD_COUNT * ACOSH_RECORD_WORDS)

typedef double (*double_unary_function)(double);
typedef float (*float_unary_function)(float);

/* Parentheses force callable C ABI symbols instead of compiler builtins. */
static double_unary_function volatile direct_acosh = (acosh);
static float_unary_function volatile direct_acoshf = (acoshf);

/* The freestanding start object writes the complete raw stream with syscall. */
uint64_t crabc_x86_64_math_acosh_records[ACOSH_RECORD_STORAGE_WORDS];
const size_t crabc_x86_64_math_acosh_record_bytes = sizeof(crabc_x86_64_math_acosh_records);

static const uint64_t binary64_inputs[ACOSH_BASE_CASES] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x000fffffffffffff),
	UINT64_C(0x0010000000000000), UINT64_C(0x3fe0000000000000),
	UINT64_C(0x3fefffffffffffff), UINT64_C(0x3ff0000000000000),
	UINT64_C(0x3ff0000000000001), UINT64_C(0x3ff2000000000000),
	UINT64_C(0x3ff8000000000000), UINT64_C(0x3fffffffffffffff),
	UINT64_C(0x4000000000000000), UINT64_C(0x4000000000000001),
	UINT64_C(0x418fffffffffffff), UINT64_C(0x4190000000000000),
	UINT64_C(0x4190000000000001), UINT64_C(0x41a0000000000000),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0x7ff0000000000000),
	UINT64_C(0x7ff8000000000041), UINT64_C(0x7ff0000000000042),
	UINT64_C(0x8000000000000001), UINT64_C(0xbfe0000000000000),
	UINT64_C(0xbff0000000000000), UINT64_C(0xbff0000000000001),
	UINT64_C(0xc000000000000000), UINT64_C(0xc190000000000000),
	UINT64_C(0xfff0000000000000), UINT64_C(0xfff8000000000041),
	UINT64_C(0xfff0000000000042), UINT64_C(0xffefffffffffffff),
};

static const uint32_t binary32_inputs[ACOSH_BASE_CASES] = {
	UINT32_C(0x00000000), UINT32_C(0x80000000), UINT32_C(0x00000001),
	UINT32_C(0x007fffff), UINT32_C(0x00800000), UINT32_C(0x3f000000),
	UINT32_C(0x3f7fffff), UINT32_C(0x3f800000), UINT32_C(0x3f800001),
	UINT32_C(0x3f900000), UINT32_C(0x3fc00000), UINT32_C(0x3fffffff),
	UINT32_C(0x40000000), UINT32_C(0x40000001), UINT32_C(0x457fffff),
	UINT32_C(0x45800000), UINT32_C(0x45800001), UINT32_C(0x46000000),
	UINT32_C(0x7f7fffff), UINT32_C(0x7f800000), UINT32_C(0x7fc00041),
	UINT32_C(0x7f800042), UINT32_C(0x80000001), UINT32_C(0xbf000000),
	UINT32_C(0xbf800000), UINT32_C(0xbf800001), UINT32_C(0xc0000000),
	UINT32_C(0xc5800000), UINT32_C(0xff800000), UINT32_C(0xffc00041),
	UINT32_C(0xff800042), UINT32_C(0xff7fffff),
};

/* Ordered bit neighborhoods cross each branch boundary in both signs. */
static const uint64_t binary64_edges[ACOSH_EDGE_CASES] = {
	UINT64_C(0x0010000000000000), UINT64_C(0x3fe0000000000000),
	UINT64_C(0x3ff0000000000000), UINT64_C(0x4000000000000000),
	UINT64_C(0x4180000000000000), UINT64_C(0x4190000000000000),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0x7ff0000000000000),
};

static const uint32_t binary32_edges[ACOSH_EDGE_CASES] = {
	UINT32_C(0x00800000), UINT32_C(0x3f000000),
	UINT32_C(0x3f800000), UINT32_C(0x40000000),
	UINT32_C(0x45000000), UINT32_C(0x45800000),
	UINT32_C(0x7f7fffff), UINT32_C(0x7f800000),
};

static const uint16_t binary64_grid_exponents[16] = {
	0, 1, 1021, 1022, 1023, 1024, 1025, 1030,
	1040, 1047, 1048, 1049, 1050, 1075, 2046, 2047,
};

static const uint8_t binary32_grid_exponents[16] = {
	0, 1, 125, 126, 127, 128, 129, 132,
	136, 137, 138, 139, 140, 160, 254, 255,
};

static uint64_t binary64_input(size_t index)
{
	if (index < ACOSH_BASE_CASES)
		return binary64_inputs[index];
	index -= ACOSH_BASE_CASES;
	if (index < 2 * ACOSH_EDGE_CASES * ACOSH_EDGE_WIDTH) {
		size_t edge = index / (2 * ACOSH_EDGE_WIDTH);
		size_t position = index % (2 * ACOSH_EDGE_WIDTH);
		uint64_t magnitude = binary64_edges[edge] +
			(uint64_t)((int)(position % ACOSH_EDGE_WIDTH) - ACOSH_EDGE_RADIUS);
		return magnitude | ((uint64_t)(position / ACOSH_EDGE_WIDTH) << 63);
	}
	index -= 2 * ACOSH_EDGE_CASES * ACOSH_EDGE_WIDTH;
	return ((uint64_t)((index & 7) == 0) << 63) |
		((uint64_t)binary64_grid_exponents[index & 15] << 52) |
		(((uint64_t)(index + 1) * UINT64_C(0x9e3779b97f4a7c15)) &
			UINT64_C(0x000fffffffffffff));
}

static uint32_t binary32_input(size_t index)
{
	if (index < ACOSH_BASE_CASES)
		return binary32_inputs[index];
	index -= ACOSH_BASE_CASES;
	if (index < 2 * ACOSH_EDGE_CASES * ACOSH_EDGE_WIDTH) {
		size_t edge = index / (2 * ACOSH_EDGE_WIDTH);
		size_t position = index % (2 * ACOSH_EDGE_WIDTH);
		uint32_t magnitude = binary32_edges[edge] +
			(uint32_t)((int)(position % ACOSH_EDGE_WIDTH) - ACOSH_EDGE_RADIUS);
		return magnitude | ((uint32_t)(position / ACOSH_EDGE_WIDTH) << 31);
	}
	index -= 2 * ACOSH_EDGE_CASES * ACOSH_EDGE_WIDTH;
	return ((uint32_t)((index & 7) == 0) << 31) |
		((uint32_t)binary32_grid_exponents[index & 15] << 23) |
		(((uint32_t)(index + 1) * UINT32_C(0x9e3779b9)) & UINT32_C(0x007fffff));
}

static const int rounding_modes[ACOSH_ROUNDING_CASES] = {
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

static uint32_t read_mxcsr(void)
{
	uint32_t value;

	__asm__ volatile("stmxcsr %0" : "=m"(value));
	return value;
}

static int record_binary64(size_t *cursor, int rounding_mode, uint64_t input)
{
	double result;
	uint32_t before;
	uint32_t after;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	before = read_mxcsr();
	if ((before & UINT32_C(0x6000)) != (uint32_t)rounding_mode << 3)
		return 5;
	result = direct_acosh(double_from_bits(input));
	after = read_mxcsr();
	if (*cursor + ACOSH_RECORD_WORDS > ACOSH_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_acosh_records[(*cursor)++] = input;
	crabc_x86_64_math_acosh_records[(*cursor)++] = double_bits(result);
	crabc_x86_64_math_acosh_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_acosh_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	crabc_x86_64_math_acosh_records[(*cursor)++] =
		((uint64_t)before << 32) | after;
	return 0;
}

static int record_binary32(size_t *cursor, int rounding_mode, uint32_t input)
{
	float result;
	uint32_t before;
	uint32_t after;

	if (fesetround(rounding_mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	before = read_mxcsr();
	if ((before & UINT32_C(0x6000)) != (uint32_t)rounding_mode << 3)
		return 5;
	result = direct_acoshf(float_from_bits(input));
	after = read_mxcsr();
	if (*cursor + ACOSH_RECORD_WORDS > ACOSH_RECORD_STORAGE_WORDS)
		return 2;
	crabc_x86_64_math_acosh_records[(*cursor)++] =
		UINT64_C(0x0000000100000000) | input;
	crabc_x86_64_math_acosh_records[(*cursor)++] = float_bits(result);
	crabc_x86_64_math_acosh_records[(*cursor)++] =
		((uint64_t)(uint32_t)rounding_mode << 32) |
		(uint32_t)fegetround();
	crabc_x86_64_math_acosh_records[(*cursor)++] =
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
	crabc_x86_64_math_acosh_records[(*cursor)++] =
		((uint64_t)before << 32) | after;
	return 0;
}

int crabc_x86_64_math_acosh_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t input_index;
	size_t mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < ACOSH_ROUNDING_CASES && status == 0;
		mode_index++) {
		for (input_index = 0; input_index < ACOSH_F64_CASES && status == 0;
			input_index++)
			status = record_binary64(&cursor, rounding_modes[mode_index],
				binary64_input(input_index));
		for (input_index = 0; input_index < ACOSH_F32_CASES && status == 0;
			input_index++)
			status = record_binary32(&cursor, rounding_modes[mode_index],
				binary32_input(input_index));
	}
	if (cursor != ACOSH_RECORD_STORAGE_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_ACOSH_FREESTANDING
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
	int status = crabc_x86_64_math_acosh_probe();

	if (status != 0)
		return status;
	return write_all(crabc_x86_64_math_acosh_records,
		sizeof(crabc_x86_64_math_acosh_records));
}
#endif
