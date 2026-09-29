/* Static Linux/x86-64 binary80 GNU sincosl differential. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native little-endian Linux/x86-64 LP64"
#endif

#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#ifndef CRABC_MATH_SINCOSL_FREESTANDING
#include <unistd.h>
#endif

#pragma STDC FENV_ACCESS ON

_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16,
	"System V binary80 storage and alignment");
_Static_assert(LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384,
	"x87 binary80 format");

#define SINCOSL_CASES 32
#define SINCOSL_MODES 4
#define SINCOSL_OUTPUT_FORMS 2
#define SINCOSL_WORDS 8
#define SINCOSL_RECORD_WORDS \
	(SINCOSL_CASES * SINCOSL_MODES * SINCOSL_OUTPUT_FORMS * SINCOSL_WORDS)

struct binary80 { uint64_t significand; uint16_t sign_exponent; };
union binary80_value {
	long double value;
	struct { uint64_t significand; uint16_t sign_exponent; unsigned char pad[6]; } bits;
};
_Static_assert(sizeof(union binary80_value) == 16 &&
	offsetof(union binary80_value, bits.sign_exponent) == 8,
	"binary80 payload occupies the first ten bytes");
_Static_assert(SINCOSL_RECORD_WORDS * sizeof(uint64_t) == 16384,
	"freestanding writer size matches record storage");

typedef void (*long_double_sincos_function)(long double, long double *, long double *);
static long_double_sincos_function volatile direct_sincosl = (sincosl);

/* The freestanding entry writes exactly 16,384 bytes. */
uint64_t crabc_x86_64_math_sincosl_records[SINCOSL_RECORD_WORDS];

static const struct binary80 inputs[SINCOSL_CASES] = {
	{UINT64_C(0), 0}, {UINT64_C(0), 0x8000},
	{UINT64_C(1), 0}, {UINT64_C(1), 0x8000},
	{UINT64_C(0x7fffffffffffffff), 0},
	{UINT64_C(0x8000000000000000), 1},
	{UINT64_C(0x8000000000000000), 0x3ffe},
	{UINT64_C(0xc90fdaa22168c234), 0x3ffe},
	{UINT64_C(0xc90fdaa22168c235), 0x3ffe},
	{UINT64_C(0xc90fdaa22168c236), 0x3ffe},
	{UINT64_C(0x8000000000000000), 0x3fff},
	{UINT64_C(0xc90fdaa22168c234), 0x3fff},
	{UINT64_C(0xc90fdaa22168c235), 0x3fff},
	{UINT64_C(0xc90fdaa22168c236), 0x3fff},
	{UINT64_C(0xc90fdaa22168c235), 0x4000},
	{UINT64_C(0xc90fdaa22168c235), 0x4001},
	{UINT64_C(0xc90fdaa22168c235), 0x4002},
	{UINT64_C(0xc90fdaa22168c235), 0xbfff},
	{UINT64_C(0xc90fdaa22168c235), 0xc000},
	{UINT64_C(0xc90fdaa22168c235), 0xc001},
	{UINT64_C(0xc90fdaa22168c235), 0xc002},
	{UINT64_C(0x8000000000000000), 0x407f},
	{UINT64_C(0x8000000000000000), 0xc07f},
	{UINT64_C(0xffffffffffffffff), 0x7ffe},
	{UINT64_C(0xffffffffffffffff), 0xfffe},
	{UINT64_C(0x8000000000000000), 0x7fff},
	{UINT64_C(0x8000000000000000), 0xffff},
	{UINT64_C(0xc000000000000041), 0x7fff},
	{UINT64_C(0xc000000000000041), 0xffff},
	{UINT64_C(0x8000000000000042), 0x7fff},
	{UINT64_C(0x8000000000000042), 0xffff},
	{UINT64_C(0x8000000000000000), 0x400e},
};

static const int modes[SINCOSL_MODES] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

static long double from_binary80(struct binary80 bits)
{
	union binary80_value value = { .bits = { bits.significand, bits.sign_exponent, {0} } };
	return value.value;
}

static void append_record(size_t *cursor, struct binary80 input,
	long double sine, long double cosine, int mode, int aliased)
{
	union binary80_value sine_bits = { .value = sine };
	union binary80_value cosine_bits = { .value = cosine };
	uint32_t mxcsr;
	uint16_t x87_status;

	__asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
	__asm__ volatile("fnstsw %0" : "=am"(x87_status));
	crabc_x86_64_math_sincosl_records[(*cursor)++] = input.significand;
	crabc_x86_64_math_sincosl_records[(*cursor)++] =
		(uint64_t)input.sign_exponent | ((uint64_t)aliased << 16);
	crabc_x86_64_math_sincosl_records[(*cursor)++] = sine_bits.bits.significand;
	crabc_x86_64_math_sincosl_records[(*cursor)++] = sine_bits.bits.sign_exponent;
	crabc_x86_64_math_sincosl_records[(*cursor)++] = cosine_bits.bits.significand;
	crabc_x86_64_math_sincosl_records[(*cursor)++] = cosine_bits.bits.sign_exponent;
	crabc_x86_64_math_sincosl_records[(*cursor)++] =
		((uint64_t)(uint32_t)mode << 32) | (uint32_t)fegetround();
	crabc_x86_64_math_sincosl_records[(*cursor)++] =
		((uint64_t)mxcsr << 32) |
		((uint64_t)(x87_status & 0x3f) << 16) |
		(uint32_t)fetestexcept(FE_ALL_EXCEPT);
}

int crabc_x86_64_math_sincosl_probe(void)
{
	fenv_t original;
	size_t cursor = 0;
	size_t mode_index, input_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < SINCOSL_MODES && status == 0; mode_index++) {
		for (input_index = 0; input_index < SINCOSL_CASES && status == 0; input_index++) {
			long double sine, cosine, aliased;
			struct binary80 input = inputs[input_index];
			int mode = modes[mode_index];

			if (fesetround(mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0) {
				status = 2;
				break;
			}
			direct_sincosl(from_binary80(input), &sine, &cosine);
			append_record(&cursor, input, sine, cosine, mode, 0);
			if (fesetround(mode) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0) {
				status = 2;
				break;
			}
			direct_sincosl(from_binary80(input), &aliased, &aliased);
			append_record(&cursor, input, aliased, 0.0L, mode, 1);
		}
	}
	if (cursor != SINCOSL_RECORD_WORDS && status == 0)
		status = 3;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_MATH_SINCOSL_FREESTANDING
int main(void)
{
	int status = crabc_x86_64_math_sincosl_probe();
	size_t remaining = sizeof(crabc_x86_64_math_sincosl_records);
	const unsigned char *cursor = (const unsigned char *)crabc_x86_64_math_sincosl_records;

	if (status != 0)
		return status;
	while (remaining != 0) {
		ssize_t count = write(1, cursor, remaining);
		if (count <= 0)
			return 5;
		cursor += count;
		remaining -= (size_t)count;
	}
	return 0;
}
#endif
