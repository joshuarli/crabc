/*
 * Native Linux/x86-64 differential for the complete
 * math.elementary-long-double capability.
 *
 * Each call goes through its project-header function-pointer type. Records
 * retain only the ten defined bytes of an x86 binary80 result (or each output
 * of sincosl), together with the x87/MXCSR exception state.
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

#pragma STDC FENV_ACCESS ON

_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16,
	"x86 binary80 storage");
_Static_assert(LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384,
	"x86 binary80 format");

typedef long double (*l_unary)(long double);
typedef long double (*l_binary)(long double, long double);
typedef long double (*l_ternary)(long double, long double, long double);
typedef void (*l_sincos)(long double, long double *, long double *);

#define DIRECT(type, name) static type direct_##name = (name)
DIRECT(l_unary, acoshl); DIRECT(l_unary, acosl);
DIRECT(l_unary, asinhl); DIRECT(l_unary, asinl);
DIRECT(l_binary, atan2l); DIRECT(l_unary, atanhl); DIRECT(l_unary, atanl);
DIRECT(l_unary, cbrtl); DIRECT(l_unary, ceill);
DIRECT(l_binary, copysignl); DIRECT(l_unary, coshl); DIRECT(l_unary, cosl);
DIRECT(l_unary, exp2l); DIRECT(l_unary, expl); DIRECT(l_unary, expm1l);
DIRECT(l_unary, fabsl); DIRECT(l_unary, floorl);
DIRECT(l_ternary, fmal); DIRECT(l_binary, fmaxl); DIRECT(l_binary, fminl);
DIRECT(l_binary, fmodl); DIRECT(l_binary, hypotl);
DIRECT(l_unary, log10l); DIRECT(l_unary, log1pl); DIRECT(l_unary, log2l);
DIRECT(l_unary, logl); DIRECT(l_binary, powl); DIRECT(l_unary, roundl);
DIRECT(l_sincos, sincosl); DIRECT(l_unary, sinhl); DIRECT(l_unary, sinl);
DIRECT(l_unary, sqrtl); DIRECT(l_unary, tanhl); DIRECT(l_unary, tanl);
DIRECT(l_unary, truncl);
#undef DIRECT

enum function_id {
	ID_ACOSHL = 1, ID_ACOSL, ID_ASINHL, ID_ASINL, ID_ATAN2L, ID_ATANHL,
	ID_ATANL, ID_CBRTL, ID_CEILL, ID_COPYSIGNL, ID_COSHL, ID_COSL,
	ID_EXP2L, ID_EXPL, ID_EXPM1L, ID_FABSL, ID_FLOORL, ID_FMAL, ID_FMAXL,
	ID_FMINL, ID_FMODL, ID_HYPOTL, ID_LOG10L, ID_LOG1PL, ID_LOG2L, ID_LOGL,
	ID_POWL, ID_ROUNDL, ID_SINCOSL, ID_SINHL, ID_SINL, ID_SQRTL, ID_TANHL,
	ID_TANL, ID_TRUNCL,
};

struct __attribute__((packed)) result_record {
	uint16_t function;
	uint16_t case_index;
	uint32_t rounding;
	uint32_t exceptions;
	uint32_t kind;
	unsigned char value[24];
};
_Static_assert(sizeof(struct result_record) == 40, "stable result record");

struct l_pair { long double left; long double right; };
struct l_triple { long double first; long double second; long double third; };

static const int rounding_modes[] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

static const long double l_values[] = {
	-INFINITY, -LDBL_MAX, -8.0L, -2.0L, -1.5L, -1.0L, -0.5L,
	-LDBL_TRUE_MIN, -0.0L, 0.0L, LDBL_TRUE_MIN, LDBL_MIN, 0.25L,
	0.5L, 1.0L, 1.5L, 2.0L, 8.0L, LDBL_MAX, INFINITY,
	__builtin_nanl("0x1234"),
};

static const struct l_pair l_pairs[] = {
	{-7.0L, 2.0L}, {-5.0L, 2.0L}, {-2.0L, 0.5L}, {-1.0L, 3.0L},
	{-0.0L, 2.0L}, {0.0L, -0.0L}, {LDBL_TRUE_MIN, -LDBL_TRUE_MIN},
	{LDBL_MIN, 2.0L}, {LDBL_MAX / 2.0L, 2.0L}, {1.0L, 0.0L},
	{INFINITY, 2.0L}, {2.0L, INFINITY}, {-INFINITY, 3.0L},
	{__builtin_nanl("0x1234"), 2.0L},
	{2.0L, __builtin_nanl("0x5678")}, {1.5L, -2.25L},
};

static const struct l_triple l_triples[] = {
	{1.0L, 1.0L, 0.0L}, {1.0L, 2.0L, -2.0L},
	{-1.0L, 2.0L, 2.0L}, {1.5L, 2.0L, -3.0L},
	{LDBL_MIN, 0.5L, -LDBL_TRUE_MIN},
	{LDBL_MAX, 0.5L, LDBL_MAX / 2.0L},
	{INFINITY, 0.0L, 1.0L}, {INFINITY, 2.0L, -INFINITY},
	{__builtin_nanl("0x1234"), 1.0L, 2.0L}, {0.0L, INFINITY, 1.0L},
	{-0.0L, 2.0L, 0.0L}, {LDBL_TRUE_MIN, 1.0L, LDBL_TRUE_MIN},
};

static long raw_write(const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;
	while (length != 0) {
		register long number __asm__("rax") = 1;
		register long descriptor __asm__("rdi") = 1;
		register const void *address __asm__("rsi") = cursor;
		register size_t count __asm__("rdx") = length;
		__asm__ volatile ("syscall" : "+a"(number)
			: "D"(descriptor), "S"(address), "d"(count)
			: "rcx", "r11", "memory");
		if (number == -4) continue;
		if (number <= 0 || (size_t)number > length) return -1;
		cursor += number;
		length -= (size_t)number;
	}
	return 0;
}

static void copy_bytes(unsigned char *destination, const unsigned char *source,
	size_t count)
{
	size_t index;
	for (index = 0; index < count; index++) destination[index] = source[index];
}

static void clear_value(unsigned char *value)
{
	size_t index;
	for (index = 0; index < 24; index++) value[index] = 0;
}

static int prepare_call(int mode)
{
	if (fesetround(mode) != 0) return -1;
	if (feclearexcept(FE_ALL_EXCEPT) != 0) return -1;
	return 0;
}

static int emit_long(uint16_t function, uint16_t index, int mode,
	long double result)
{
	union { long double value; unsigned char bytes[16]; } bits = { result };
	struct result_record record;
	record.function = function;
	record.case_index = index;
	record.rounding = (uint32_t)mode;
	record.exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
	record.kind = 1;
	clear_value(record.value);
	copy_bytes(record.value, bits.bytes, 10);
	return raw_write(&record, sizeof(record)) == 0 ? 0 : -1;
}

static int emit_pair(uint16_t function, uint16_t index, int mode,
	long double first, long double second)
{
	union { long double value; unsigned char bytes[16]; } first_bits = { first };
	union { long double value; unsigned char bytes[16]; } second_bits = { second };
	struct result_record record;
	record.function = function;
	record.case_index = index;
	record.rounding = (uint32_t)mode;
	record.exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
	record.kind = 2;
	clear_value(record.value);
	copy_bytes(record.value, first_bits.bytes, 10);
	copy_bytes(record.value + 10, second_bits.bytes, 10);
	return raw_write(&record, sizeof(record)) == 0 ? 0 : -1;
}

static int run_unary(uint16_t function, l_unary operation)
{
	size_t mode_index, value_index;
	for (mode_index = 0; mode_index < sizeof(rounding_modes) / sizeof(rounding_modes[0]); mode_index++) {
		for (value_index = 0; value_index < sizeof(l_values) / sizeof(l_values[0]); value_index++) {
			if (prepare_call(rounding_modes[mode_index]) != 0 ||
				emit_long(function, (uint16_t)value_index, rounding_modes[mode_index],
					operation(l_values[value_index])) != 0) return -1;
		}
	}
	return 0;
}

static int run_binary(uint16_t function, l_binary operation)
{
	size_t mode_index, pair_index;
	for (mode_index = 0; mode_index < sizeof(rounding_modes) / sizeof(rounding_modes[0]); mode_index++) {
		for (pair_index = 0; pair_index < sizeof(l_pairs) / sizeof(l_pairs[0]); pair_index++) {
			if (prepare_call(rounding_modes[mode_index]) != 0 ||
				emit_long(function, (uint16_t)pair_index, rounding_modes[mode_index],
					operation(l_pairs[pair_index].left, l_pairs[pair_index].right)) != 0) return -1;
		}
	}
	return 0;
}

static int run_ternary(uint16_t function, l_ternary operation)
{
	size_t mode_index, triple_index;
	for (mode_index = 0; mode_index < sizeof(rounding_modes) / sizeof(rounding_modes[0]); mode_index++) {
		for (triple_index = 0; triple_index < sizeof(l_triples) / sizeof(l_triples[0]); triple_index++) {
			if (prepare_call(rounding_modes[mode_index]) != 0 ||
				emit_long(function, (uint16_t)triple_index, rounding_modes[mode_index],
					operation(l_triples[triple_index].first,
						l_triples[triple_index].second,
						l_triples[triple_index].third)) != 0) return -1;
		}
	}
	return 0;
}

static int run_sincos(void)
{
	size_t mode_index, value_index;
	for (mode_index = 0; mode_index < sizeof(rounding_modes) / sizeof(rounding_modes[0]); mode_index++) {
		for (value_index = 0; value_index < sizeof(l_values) / sizeof(l_values[0]); value_index++) {
			long double sine, cosine;
			if (prepare_call(rounding_modes[mode_index]) != 0) return -1;
			direct_sincosl(l_values[value_index], &sine, &cosine);
			if (emit_pair(ID_SINCOSL, (uint16_t)value_index,
				rounding_modes[mode_index], sine, cosine) != 0) return -1;
		}
	}
	return 0;
}

int crabc_x86_64_math_elementary_long_double_probe(void)
{
	return run_unary(ID_ACOSHL, direct_acoshl) ||
		run_unary(ID_ACOSL, direct_acosl) ||
		run_unary(ID_ASINHL, direct_asinhl) ||
		run_unary(ID_ASINL, direct_asinl) ||
		run_binary(ID_ATAN2L, direct_atan2l) ||
		run_unary(ID_ATANHL, direct_atanhl) ||
		run_unary(ID_ATANL, direct_atanl) ||
		run_unary(ID_CBRTL, direct_cbrtl) ||
		run_unary(ID_CEILL, direct_ceill) ||
		run_binary(ID_COPYSIGNL, direct_copysignl) ||
		run_unary(ID_COSHL, direct_coshl) ||
		run_unary(ID_COSL, direct_cosl) ||
		run_unary(ID_EXP2L, direct_exp2l) ||
		run_unary(ID_EXPL, direct_expl) ||
		run_unary(ID_EXPM1L, direct_expm1l) ||
		run_unary(ID_FABSL, direct_fabsl) ||
		run_unary(ID_FLOORL, direct_floorl) ||
		run_ternary(ID_FMAL, direct_fmal) ||
		run_binary(ID_FMAXL, direct_fmaxl) ||
		run_binary(ID_FMINL, direct_fminl) ||
		run_binary(ID_FMODL, direct_fmodl) ||
		run_binary(ID_HYPOTL, direct_hypotl) ||
		run_unary(ID_LOG10L, direct_log10l) ||
		run_unary(ID_LOG1PL, direct_log1pl) ||
		run_unary(ID_LOG2L, direct_log2l) ||
		run_unary(ID_LOGL, direct_logl) ||
		run_binary(ID_POWL, direct_powl) ||
		run_unary(ID_ROUNDL, direct_roundl) ||
		run_sincos() ||
		run_unary(ID_SINHL, direct_sinhl) ||
		run_unary(ID_SINL, direct_sinl) ||
		run_unary(ID_SQRTL, direct_sqrtl) ||
		run_unary(ID_TANHL, direct_tanhl) ||
		run_unary(ID_TANL, direct_tanl) ||
		run_unary(ID_TRUNCL, direct_truncl);
}

#ifndef CRABC_MATH_ELEMENTARY_LONG_DOUBLE_FREESTANDING
int main(void)
{
	return crabc_x86_64_math_elementary_long_double_probe();
}
#endif
