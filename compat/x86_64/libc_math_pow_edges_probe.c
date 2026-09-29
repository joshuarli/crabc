/* Exact pow/powf bit and exception records across finite and exceptional edges. */
#include <fenv.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>

#pragma STDC FENV_ACCESS ON

#define BASE_COUNT 24
#define EXPONENT_COUNT 25
#define MODE_COUNT 4
#define RECORD_WORDS 5
#define RECORD_COUNT (2 * BASE_COUNT * EXPONENT_COUNT * MODE_COUNT)

static double (*volatile call_pow)(double, double) = pow;
static float (*volatile call_powf)(float, float) = powf;

uint64_t crabc_x86_64_math_pow_records[RECORD_COUNT * RECORD_WORDS];
const uint64_t crabc_x86_64_math_pow_record_bytes =
	sizeof(crabc_x86_64_math_pow_records);

/* Bit patterns keep the source and candidate operands identical. */
static const uint64_t double_bases[BASE_COUNT] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x8000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x8000000000000001),
	UINT64_C(0x000fffffffffffff), UINT64_C(0x0010000000000000),
	UINT64_C(0x3fefffffffffffff), UINT64_C(0x3ff0000000000000),
	UINT64_C(0x3ff0000000000001), UINT64_C(0xbfefffffffffffff),
	UINT64_C(0xbff0000000000000), UINT64_C(0xbff0000000000001),
	UINT64_C(0xc000000000000000), UINT64_C(0x4000000000000000),
	UINT64_C(0x7fefffffffffffff), UINT64_C(0xffefffffffffffff),
	UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
	UINT64_C(0x7ff8000000000041), UINT64_C(0x7ff0000000000042),
	UINT64_C(0x3fdfffffffffffff), UINT64_C(0x3ff0000000000002),
	UINT64_C(0xbff0000000000002), UINT64_C(0xc010000000000000),
};
static const uint64_t double_exponents[EXPONENT_COUNT] = {
	UINT64_C(0xfff0000000000000), UINT64_C(0xc090cc0000000000),
	UINT64_C(0xc090c80000000000), UINT64_C(0xc000000000000000),
	UINT64_C(0xbff8000000000000), UINT64_C(0xbff0000000000000),
	UINT64_C(0xbfe0000000000000), UINT64_C(0x8000000000000001),
	UINT64_C(0x8000000000000000), UINT64_C(0x0000000000000000),
	UINT64_C(0x0000000000000001), UINT64_C(0x3fe0000000000000),
	UINT64_C(0x3fefffffffffffff), UINT64_C(0x3ff0000000000000),
	UINT64_C(0x3ff0000000000001), UINT64_C(0x3ff8000000000000),
	UINT64_C(0x4000000000000000), UINT64_C(0x4090000000000000),
	UINT64_C(0x7ff0000000000000), UINT64_C(0x7ff8000000000043),
	UINT64_C(0xc008000000000000), UINT64_C(0x4008000000000000),
	UINT64_C(0x408ff80000000000), UINT64_C(0xc090d00000000000),
	UINT64_C(0x7ff0000000000044),
};
static const uint32_t float_bases[BASE_COUNT] = {
	UINT32_C(0x00000000), UINT32_C(0x80000000),
	UINT32_C(0x00000001), UINT32_C(0x80000001),
	UINT32_C(0x007fffff), UINT32_C(0x00800000),
	UINT32_C(0x3f7fffff), UINT32_C(0x3f800000),
	UINT32_C(0x3f800001), UINT32_C(0xbf7fffff),
	UINT32_C(0xbf800000), UINT32_C(0xbf800001),
	UINT32_C(0xc0000000), UINT32_C(0x40000000),
	UINT32_C(0x7f7fffff), UINT32_C(0xff7fffff),
	UINT32_C(0x7f800000), UINT32_C(0xff800000),
	UINT32_C(0x7fc00041), UINT32_C(0x7f800042),
	UINT32_C(0x3effffff), UINT32_C(0x3f800002),
	UINT32_C(0xbf800002), UINT32_C(0xc0800000),
};
static const uint32_t float_exponents[EXPONENT_COUNT] = {
	UINT32_C(0xff800000), UINT32_C(0xc3160000),
	UINT32_C(0xc3140000), UINT32_C(0xc0000000),
	UINT32_C(0xbfc00000), UINT32_C(0xbf800000),
	UINT32_C(0xbf000000), UINT32_C(0x80000001),
	UINT32_C(0x80000000), UINT32_C(0x00000000),
	UINT32_C(0x00000001), UINT32_C(0x3f000000),
	UINT32_C(0x3f7fffff), UINT32_C(0x3f800000),
	UINT32_C(0x3f800001), UINT32_C(0x3fc00000),
	UINT32_C(0x40000000), UINT32_C(0x43000000),
	UINT32_C(0x7f800000), UINT32_C(0x7fc00043),
	UINT32_C(0xc0400000), UINT32_C(0x40400000),
	UINT32_C(0x42fe0000), UINT32_C(0xc3150000),
	UINT32_C(0x7f800044),
};
static const int modes[MODE_COUNT] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

static double as_double(uint64_t bits)
{
	union { uint64_t bits; double value; } cast = { .bits = bits };
	return cast.value;
}
static float as_float(uint32_t bits)
{
	union { uint32_t bits; float value; } cast = { .bits = bits };
	return cast.value;
}
static uint64_t double_bits(double value)
{
	union { uint64_t bits; double value; } cast = { .value = value };
	return cast.bits;
}
static uint32_t float_bits(float value)
{
	union { uint32_t bits; float value; } cast = { .value = value };
	return cast.bits;
}

int crabc_x86_64_math_pow_probe(void)
{
	fenv_t saved;
	size_t cursor = 0;
	size_t mode, base, exponent;
	int precision;

	if (fegetenv(&saved) || fesetenv(FE_DFL_ENV)) return 1;
	for (mode = 0; mode < MODE_COUNT; mode++) {
		for (precision = 0; precision != 2; precision++) {
			for (base = 0; base < BASE_COUNT; base++) {
				for (exponent = 0; exponent < EXPONENT_COUNT; exponent++) {
					uint64_t result;
					if (fesetround(modes[mode]) || feclearexcept(FE_ALL_EXCEPT)) return 2;
					if (precision == 0) {
						result = double_bits(call_pow(as_double(double_bases[base]),
							as_double(double_exponents[exponent])));
						crabc_x86_64_math_pow_records[cursor++] = double_bases[base];
						crabc_x86_64_math_pow_records[cursor++] = double_exponents[exponent];
					} else {
						result = float_bits(call_powf(as_float(float_bases[base]),
							as_float(float_exponents[exponent])));
						crabc_x86_64_math_pow_records[cursor++] =
							UINT64_C(0x100000000) | float_bases[base];
						crabc_x86_64_math_pow_records[cursor++] = float_exponents[exponent];
					}
					crabc_x86_64_math_pow_records[cursor++] = result;
					crabc_x86_64_math_pow_records[cursor++] =
						((uint64_t)(uint32_t)modes[mode] << 32) | (uint32_t)fegetround();
					crabc_x86_64_math_pow_records[cursor++] =
						(uint32_t)fetestexcept(FE_ALL_EXCEPT);
				}
			}
		}
	}
	if (cursor != RECORD_COUNT * RECORD_WORDS) return 3;
	return fesetenv(&saved) != 0 ? 4 : 0;
}
