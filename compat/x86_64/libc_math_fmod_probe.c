/*
 * Static Linux/x86-64 fmod/fmodf C ABI regression.
 *
 * This fixture selects only binary64 `fmod` and binary32 `fmodf`. It runs
 * unchanged against pinned musl 1.2.6 and one freestanding crabc archive.
 * Function pointers prevent compiler builtins from replacing the named C ABI
 * calls. The checks cover the source's integer reduction loop, signed-zero
 * result, subnormal normalization, NaN/domain-error boundary, and the narrow
 * fenv effects needed by those operations; this is not a long-double,
 * rounding/truncation, special, complex, or general libm claim.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stdint.h>

typedef double (*double_binary_function)(double, double);
typedef float (*float_binary_function)(float, float);

/* Parentheses force callable C ABI symbols rather than compiler builtins. */
static double_binary_function volatile direct_fmod = (fmod);
static float_binary_function volatile direct_fmodf = (fmodf);

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

/* The same binary stream is written by pinned musl and the static candidate. */
struct remainder_record {
	uint64_t x;
	uint64_t y;
	uint64_t result;
	uint32_t case_id;
	uint32_t requested_mode;
	uint32_t observed_mode;
	uint32_t exceptions;
};

static int write_record(const struct remainder_record *record)
{
	const unsigned char *data = (const unsigned char *)record;
	unsigned long remaining = sizeof(*record);

	while (remaining != 0) {
		long written;
		__asm__ volatile("syscall" : "=a"(written) :
			"a"(1), "D"(1), "S"(data), "d"(remaining) :
			"rcx", "r11", "memory");
		if (written <= 0)
			return 1;
		data += written;
		remaining -= (unsigned long)written;
	}
	return 0;
}

static int observe_double(uint32_t id, int mode, int sticky, uint64_t x, uint64_t y)
{
	struct remainder_record record = {0};
	if (feclearexcept(FE_ALL_EXCEPT) != 0 ||
		(sticky && feraiseexcept(FE_DIVBYZERO) != 0))
		return 1;
	record.x = x;
	record.y = y;
	record.case_id = id | ((uint32_t)sticky << 31);
	record.requested_mode = (uint32_t)mode;
	record.result = double_bits(direct_fmod(double_from_bits(x), double_from_bits(y)));
	record.observed_mode = (uint32_t)fegetround();
	record.exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return record.observed_mode != record.requested_mode || write_record(&record);
}

static int observe_float(uint32_t id, int mode, int sticky, uint32_t x, uint32_t y)
{
	struct remainder_record record = {0};
	if (feclearexcept(FE_ALL_EXCEPT) != 0 ||
		(sticky && feraiseexcept(FE_DIVBYZERO) != 0))
		return 1;
	record.x = x;
	record.y = y;
	record.case_id = id | ((uint32_t)sticky << 31);
	record.requested_mode = (uint32_t)mode;
	record.result = float_bits(direct_fmodf(float_from_bits(x), float_from_bits(y)));
	record.observed_mode = (uint32_t)fegetround();
	record.exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
	return record.observed_mode != record.requested_mode || write_record(&record);
}

static uint64_t next_bits(uint64_t *state)
{
	uint64_t value = *state;
	value ^= value << 13;
	value ^= value >> 7;
	value ^= value << 17;
	*state = value;
	return value;
}

static int emit_remainder_records(void)
{
	static const struct { uint64_t x, y; } double_edges[] = {
		{ 0, UINT64_C(0x3ff0000000000000) },
		{ UINT64_C(0x8000000000000000), UINT64_C(0x3ff0000000000000) },
		{ UINT64_C(0xc010000000000000), UINT64_C(0x4000000000000000) },
		{ UINT64_C(0xbff0000000000000), UINT64_C(0xbff0000000000000) },
		{ 1, 2 }, { 2, 1 },
		{ UINT64_C(0x000fffffffffffff), 1 },
		{ UINT64_C(0x0010000000000000), UINT64_C(0x000fffffffffffff) },
		{ UINT64_C(0x0010000000000001), UINT64_C(0x0010000000000000) },
		{ UINT64_C(0x7fefffffffffffff), 1 },
		{ UINT64_C(0x7fefffffffffffff), UINT64_C(0x0010000000000001) },
		{ UINT64_C(0x433fffffffffffff), UINT64_C(0x4026000000000000) },
		{ UINT64_C(0x3ff0000000000000), 0 },
		{ UINT64_C(0x7ff0000000000000), UINT64_C(0x3ff0000000000000) },
		{ UINT64_C(0x3ff0000000000000), UINT64_C(0x7ff0000000000000) },
		{ UINT64_C(0x7ff8000000000041), UINT64_C(0x3ff0000000000000) },
		{ UINT64_C(0x3ff0000000000000), UINT64_C(0x7ff8000000000041) },
		{ UINT64_C(0x7ff0000000000042), UINT64_C(0x3ff0000000000000) },
		{ UINT64_C(0x3ff0000000000000), UINT64_C(0x7ff0000000000042) },
	};
	static const struct { uint32_t x, y; } float_edges[] = {
		{ 0, UINT32_C(0x3f800000) },
		{ UINT32_C(0x80000000), UINT32_C(0x3f800000) },
		{ UINT32_C(0xc0800000), UINT32_C(0x40000000) },
		{ UINT32_C(0xbf800000), UINT32_C(0xbf800000) },
		{ 1, 2 }, { 2, 1 },
		{ UINT32_C(0x007fffff), 1 },
		{ UINT32_C(0x00800000), UINT32_C(0x007fffff) },
		{ UINT32_C(0x00800001), UINT32_C(0x00800000) },
		{ UINT32_C(0x7f7fffff), 1 },
		{ UINT32_C(0x7f7fffff), UINT32_C(0x00800001) },
		{ UINT32_C(0x4b7fffff), UINT32_C(0x41300000) },
		{ UINT32_C(0x3f800000), 0 },
		{ UINT32_C(0x7f800000), UINT32_C(0x3f800000) },
		{ UINT32_C(0x3f800000), UINT32_C(0x7f800000) },
		{ UINT32_C(0x7fc00041), UINT32_C(0x3f800000) },
		{ UINT32_C(0x3f800000), UINT32_C(0x7fc00041) },
		{ UINT32_C(0x7f800042), UINT32_C(0x3f800000) },
		{ UINT32_C(0x3f800000), UINT32_C(0x7f800042) },
	};
	static const int modes[] = {
		FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
	};
	uint64_t state;
	uint32_t id;

	for (unsigned int mode = 0; mode < 4; mode++) {
		if (fesetround(modes[mode]) != 0)
			return 1;
		for (int sticky = 0; sticky < 2; sticky++) {
			id = 0;
			for (unsigned int i = 0; i < sizeof(double_edges) / sizeof(double_edges[0]); i++)
				if (observe_double(id++, modes[mode], sticky,
					double_edges[i].x, double_edges[i].y))
					return 2;
			for (unsigned int i = 0; i < sizeof(float_edges) / sizeof(float_edges[0]); i++)
				if (observe_float(id++, modes[mode], sticky,
					float_edges[i].x, float_edges[i].y))
					return 3;
			/* Exercise both sides of exact quotient and divisor-power boundaries. */
			for (unsigned int i = 0; i < 64; i++) {
				uint64_t y = (uint64_t)(1 + i * 32) << 52;
				uint64_t twice = y + (UINT64_C(1) << 52);
				if (observe_double(id++, modes[mode], sticky, twice - 1, y) ||
					observe_double(id++, modes[mode], sticky, twice, y + 1) ||
					observe_double(id++, modes[mode], sticky, twice + 1, y - 1))
					return 4;
			}
			for (unsigned int i = 0; i < 32; i++) {
				uint32_t y = (1 + i * 8) << 23;
				uint32_t twice = y + (UINT32_C(1) << 23);
				if (observe_float(id++, modes[mode], sticky, twice - 1, y) ||
					observe_float(id++, modes[mode], sticky, twice, y + 1) ||
					observe_float(id++, modes[mode], sticky, twice + 1, y - 1))
					return 5;
			}
			state = UINT64_C(0x4c6f6e67466d6f64);
			for (unsigned int i = 0; i < 256; i++) {
				uint64_t x = next_bits(&state);
				uint64_t y = next_bits(&state);
				uint64_t x_exp = 1 + (i * 997U) % 2046U;
				uint64_t y_exp = 1 + (i * 619U) % 2046U;
				x = (x & UINT64_C(0x800fffffffffffff)) | (x_exp << 52);
				y = (y & UINT64_C(0x800fffffffffffff)) | (y_exp << 52);
				if (observe_double(id++, modes[mode], sticky, x, y))
					return 6;
			}
			for (unsigned int i = 0; i < 256; i++) {
				uint32_t x = (uint32_t)next_bits(&state);
				uint32_t y = (uint32_t)next_bits(&state);
				uint32_t x_exp = 1 + (i * 107U) % 254U;
				uint32_t y_exp = 1 + (i * 71U) % 254U;
				x = (x & UINT32_C(0x807fffff)) | (x_exp << 23);
				y = (y & UINT32_C(0x807fffff)) | (y_exp << 23);
				if (observe_float(id++, modes[mode], sticky, x, y))
					return 7;
			}
		}
	}
	return 0;
}

static int check_binary64_values(void)
{
	volatile double negative_zero = -0.0;
	volatile double quiet_nan = double_from_bits(UINT64_C(0x7ff8000000000041));
	volatile double signaling_nan = double_from_bits(UINT64_C(0x7ff0000000000042));

	if (double_bits(direct_fmod(5.5, 2.0)) != UINT64_C(0x3ff8000000000000) ||
		double_bits(direct_fmod(-5.5, 2.0)) != UINT64_C(0xbff8000000000000) ||
		double_bits(direct_fmod(5.5, -2.0)) != UINT64_C(0x3ff8000000000000) ||
		double_bits(direct_fmod(-0.75, 2.0)) != UINT64_C(0xbfe8000000000000))
		return 1;
	if (double_bits(direct_fmod(-4.0, 2.0)) != UINT64_C(0x8000000000000000) ||
		double_bits(direct_fmod(negative_zero, 3.0)) != UINT64_C(0x8000000000000000) ||
		double_bits(direct_fmod(double_from_bits(UINT64_C(0x0000000000000001)),
			double_from_bits(UINT64_C(0x0000000000000002)))) !=
			UINT64_C(0x0000000000000001) ||
		double_bits(direct_fmod(double_from_bits(UINT64_C(0x0000000000000002)),
			double_from_bits(UINT64_C(0x0000000000000001)))) != 0)
		return 2;
	if (double_bits(direct_fmod(double_from_bits(UINT64_C(0x433fffffffffffff)), 11.0)) !=
		UINT64_C(0x401c000000000000))
		return 3;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 4;
	if (double_bits(direct_fmod(quiet_nan, 1.0)) != UINT64_C(0x7ff8000000000041) ||
		double_bits(direct_fmod(1.0, quiet_nan)) != UINT64_C(0x7ff8000000000041) ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 5;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 6;
	if (!isnan(direct_fmod(signaling_nan, 1.0)) ||
		!isnan(direct_fmod(1.0, signaling_nan)) ||
		fetestexcept(FE_ALL_EXCEPT) != FE_INVALID)
		return 7;
	return 0;
}

static int check_binary32_values(void)
{
	volatile float negative_zero = -0.0f;
	volatile float quiet_nan = float_from_bits(UINT32_C(0x7fc00041));
	volatile float signaling_nan = float_from_bits(UINT32_C(0x7f800042));

	if (float_bits(direct_fmodf(5.5f, 2.0f)) != UINT32_C(0x3fc00000) ||
		float_bits(direct_fmodf(-5.5f, 2.0f)) != UINT32_C(0xbfc00000) ||
		float_bits(direct_fmodf(5.5f, -2.0f)) != UINT32_C(0x3fc00000) ||
		float_bits(direct_fmodf(-0.75f, 2.0f)) != UINT32_C(0xbf400000))
		return 1;
	if (float_bits(direct_fmodf(-4.0f, 2.0f)) != UINT32_C(0x80000000) ||
		float_bits(direct_fmodf(negative_zero, 3.0f)) != UINT32_C(0x80000000) ||
		float_bits(direct_fmodf(float_from_bits(UINT32_C(0x00000001)),
			float_from_bits(UINT32_C(0x00000002)))) != UINT32_C(0x00000001) ||
		float_bits(direct_fmodf(float_from_bits(UINT32_C(0x00000002)),
			float_from_bits(UINT32_C(0x00000001)))) != 0)
		return 2;
	if (float_bits(direct_fmodf(float_from_bits(UINT32_C(0x4b7fffff)), 11.0f)) !=
		UINT32_C(0x40800000))
		return 3;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 4;
	if (float_bits(direct_fmodf(quiet_nan, 1.0f)) != UINT32_C(0x7fc00041) ||
		float_bits(direct_fmodf(1.0f, quiet_nan)) != UINT32_C(0x7fc00041) ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 5;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 6;
	if (!isnan(direct_fmodf(signaling_nan, 1.0f)) ||
		!isnan(direct_fmodf(1.0f, signaling_nan)) ||
		fetestexcept(FE_ALL_EXCEPT) != FE_INVALID)
		return 7;
	return 0;
}

static int check_fenv_boundary(void)
{
	static const int modes[4] = {
		FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
	};
	int index;

	for (index = 0; index < 4; index++) {
		if (fesetround(modes[index]) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
			return 1 + index;
		if (double_bits(direct_fmod(-5.5, 2.0)) != UINT64_C(0xbff8000000000000) ||
			float_bits(direct_fmodf(-5.5f, 2.0f)) != UINT32_C(0xbfc00000) ||
			fegetround() != modes[index] || fetestexcept(FE_ALL_EXCEPT) != 0)
			return 5 + index;
	}
	if (fesetround(FE_TONEAREST) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0 ||
		feraiseexcept(FE_DIVBYZERO) != 0)
		return 9;
	if (double_bits(direct_fmod(5.5, 2.0)) != UINT64_C(0x3ff8000000000000) ||
		float_bits(direct_fmodf(5.5f, 2.0f)) != UINT32_C(0x3fc00000) ||
		fetestexcept(FE_ALL_EXCEPT) != FE_DIVBYZERO)
		return 10;
	return 0;
}

static int check_invalid_domain(void)
{
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	if (!isnan(direct_fmod(1.0, 0.0)) ||
		fetestexcept(FE_ALL_EXCEPT) != FE_INVALID)
		return 2;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 3;
	if (!isnan(direct_fmodf(1.0f, 0.0f)) ||
		fetestexcept(FE_ALL_EXCEPT) != FE_INVALID)
		return 4;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 5;
	if (!isnan(direct_fmod(HUGE_VAL, 1.0)) ||
		!isnan(direct_fmodf(HUGE_VALF, 1.0f)) ||
		fetestexcept(FE_ALL_EXCEPT) != FE_INVALID)
		return 6;
	return 0;
}

int crabc_x86_64_math_fmod_probe(void)
{
	fenv_t original;
	int status;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	status = check_binary64_values();
	if (status == 0)
		status = check_binary32_values() == 0 ? 0 : 20;
	if (status == 0)
		status = check_fenv_boundary() == 0 ? 0 : 40;
	if (status == 0)
		status = check_invalid_domain() == 0 ? 0 : 60;
	if (status == 0)
		status = emit_remainder_records() == 0 ? 0 : 70;
	if (fesetenv(&original) != 0 && status == 0)
		status = 80;
	return status;
}

#ifndef CRABC_MATH_FMOD_FREESTANDING
int main(void)
{
	return crabc_x86_64_math_fmod_probe();
}
#endif
