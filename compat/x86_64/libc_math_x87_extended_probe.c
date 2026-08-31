/*
 * Native Linux/x86-64 selected x87 long-double math differential.
 *
 * The runner compares this fixture's complete pinned-musl and static-candidate
 * byte streams. Records contain only the defined 10-byte binary80 payload,
 * x86 exception flags, and integer/quotient results; long-double padding is
 * never observed. Fixture-local SYS_write is evidence plumbing only.
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

typedef long double (*unary_function)(long double);
typedef long double (*binary_function)(long double, long double);
typedef long double (*remquo_function)(long double, long double, int *);
typedef long (*long_integer_function)(long double);
typedef long long (*long_long_integer_function)(long double);

static unary_function direct_acosl = (acosl);
static unary_function direct_asinl = (asinl);
static unary_function direct_atanl = (atanl);
static binary_function direct_atan2l = (atan2l);
static unary_function direct_ceill = (ceill);
static unary_function direct_exp2l = (exp2l);
static unary_function direct_expl = (expl);
static unary_function direct_expm1l = (expm1l);
static unary_function direct_fabsl = (fabsl);
static unary_function direct_floorl = (floorl);
static binary_function direct_fmodl = (fmodl);
static unary_function direct_log10l = (log10l);
static unary_function direct_log1pl = (log1pl);
static unary_function direct_log2l = (log2l);
static unary_function direct_logl = (logl);
static long_integer_function direct_lrintl = (lrintl);
static long_long_integer_function direct_llrintl = (llrintl);
static unary_function direct_rintl = (rintl);
static binary_function direct_remainderl = (remainderl);
static remquo_function direct_remquol = (remquol);
static unary_function direct_sqrtl = (sqrtl);
static unary_function direct_truncl = (truncl);

enum function_id {
	ID_ACOSL = 1, ID_ASINL, ID_ATANL, ID_ATAN2L, ID_CEILL, ID_EXP2L,
	ID_EXPL, ID_EXPM1L, ID_FABSL, ID_FLOORL, ID_FMODL, ID_LOG10L,
	ID_LOG1PL, ID_LOG2L, ID_LOGL, ID_LRINTL, ID_LLRINTL, ID_RINTL,
	ID_REMAINDERL, ID_REMQUOL, ID_SQRTL, ID_TRUNCL,
};

struct __attribute__((packed)) result_record {
	uint16_t function;
	uint16_t case_index;
	uint32_t rounding;
	uint32_t exceptions;
	int32_t quotient;
	unsigned char value[10];
};
_Static_assert(sizeof(struct result_record) == 26, "stable result record");

union long_double_bits { long double value; unsigned char bytes[16]; };
struct binary_input { long double left; long double right; };

static const int rounding_modes[] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};
static const long double inverse_inputs[] = {
	-2.0L, -1.0L, -0.5L, -0.0L, 0.0L, LDBL_TRUE_MIN, 0.5L,
	1.0L, 2.0L, HUGE_VALL, __builtin_nanl(""),
};
static const long double exponential_inputs[] = {
	-HUGE_VALL, -16400.0L, -65.0L, -1.0L, -0x1p-65L, -0.0L,
	0.0L, 0x1p-65L, 0.5L, 1.0L, 64.0L, 16384.0L, HUGE_VALL,
	__builtin_nanl(""),
};
static const long double logarithm_inputs[] = {
	-2.0L, -1.0L, -0.0L, 0.0L, LDBL_TRUE_MIN, 0x1p-16382L,
	0.5L, 1.0L, 1.5L, 2.0L, LDBL_MAX, HUGE_VALL,
	__builtin_nanl(""),
};
static const long double exact_inputs[] = {
	-HUGE_VALL, -LDBL_MAX, -2.5L, -1.5L, -1.0L, -0.5L,
	-LDBL_TRUE_MIN, -0.0L, 0.0L, LDBL_TRUE_MIN, 0.5L, 1.0L,
	1.5L, 2.5L, LDBL_MAX, HUGE_VALL, __builtin_nanl(""),
};
static const long double sqrt_inputs[] = {
	-4.0L, -LDBL_TRUE_MIN, -0.0L, 0.0L, LDBL_TRUE_MIN,
	0x1p-16382L, 0.5L, 2.0L, 4.0L, LDBL_MAX, HUGE_VALL,
	__builtin_nanl(""),
};
static const struct binary_input atan2_inputs[] = {
	{-0.0L, -0.0L}, {-0.0L, 0.0L}, {0.0L, -0.0L}, {0.0L, 0.0L},
	{-1.0L, -1.0L}, {-1.0L, 1.0L}, {1.0L, -1.0L}, {1.0L, 1.0L},
	{-HUGE_VALL, HUGE_VALL}, {HUGE_VALL, -HUGE_VALL},
	{__builtin_nanl(""), 1.0L}, {1.0L, __builtin_nanl("")},
};
static const struct binary_input remainder_inputs[] = {
	{-7.0L, 2.0L}, {-5.0L, 2.0L}, {-3.0L, 2.0L}, {-0.0L, 2.0L},
	{0.0L, 2.0L}, {3.0L, 2.0L}, {5.0L, 2.0L}, {7.0L, 2.0L},
	{LDBL_MAX, 3.0L}, {LDBL_TRUE_MIN, 2.0L}, {1.0L, 0.0L},
	{HUGE_VALL, 2.0L}, {2.0L, HUGE_VALL},
	{__builtin_nanl(""), 2.0L}, {2.0L, __builtin_nanl("")},
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

static int emit_long_double(uint16_t function, uint16_t case_index,
	int rounding, int quotient, long double value)
{
	struct result_record record;
	union long_double_bits bits;
	unsigned int index;
	record.function = function;
	record.case_index = case_index;
	record.rounding = (uint32_t)rounding;
	record.exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
	record.quotient = quotient;
	bits.value = value;
	for (index = 0; index < 10; index++) record.value[index] = bits.bytes[index];
	return raw_write(&record, sizeof(record)) == 0 ? 0 : -1;
}

static int emit_integer(uint16_t function, uint16_t case_index, int rounding,
	long long value)
{
	struct result_record record;
	unsigned long long bits = (unsigned long long)value;
	unsigned int index;
	record.function = function;
	record.case_index = case_index;
	record.rounding = (uint32_t)rounding;
	record.exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
	record.quotient = 0;
	for (index = 0; index < 10; index++) {
		record.value[index] = (unsigned char)bits;
		bits >>= 8;
	}
	return raw_write(&record, sizeof(record)) == 0 ? 0 : -1;
}

static int run_unary(uint16_t function, unary_function operation,
	const long double *inputs, size_t count)
{
	size_t mode, index;
	for (mode = 0; mode < 4; mode++) {
		if (fesetround(rounding_modes[mode]) != 0) return -1;
		for (index = 0; index < count; index++) {
			long double result;
			if (feclearexcept(FE_ALL_EXCEPT) != 0) return -1;
			result = operation(inputs[index]);
			if (emit_long_double(function, (uint16_t)index,
				rounding_modes[mode], 0, result) != 0) return -1;
		}
	}
	return 0;
}

static int run_binary(uint16_t function, binary_function operation,
	const struct binary_input *inputs, size_t count)
{
	size_t mode, index;
	for (mode = 0; mode < 4; mode++) {
		if (fesetround(rounding_modes[mode]) != 0) return -1;
		for (index = 0; index < count; index++) {
			long double result;
			if (feclearexcept(FE_ALL_EXCEPT) != 0) return -1;
			result = operation(inputs[index].left, inputs[index].right);
			if (emit_long_double(function, (uint16_t)index,
				rounding_modes[mode], 0, result) != 0) return -1;
		}
	}
	return 0;
}

static int run_remquo(void)
{
	size_t mode, index;
	for (mode = 0; mode < 4; mode++) {
		if (fesetround(rounding_modes[mode]) != 0) return -1;
		for (index = 0; index < sizeof(remainder_inputs)/sizeof(remainder_inputs[0]); index++) {
			long double result;
			int quotient = 0x5a5a5a5a;
			if (feclearexcept(FE_ALL_EXCEPT) != 0) return -1;
			result = direct_remquol(remainder_inputs[index].left,
				remainder_inputs[index].right, &quotient);
			if (emit_long_double(ID_REMQUOL, (uint16_t)index,
				rounding_modes[mode], quotient, result) != 0) return -1;
		}
	}
	return 0;
}

static int run_integer_conversions(void)
{
	size_t mode, index;
	for (mode = 0; mode < 4; mode++) {
		if (fesetround(rounding_modes[mode]) != 0) return -1;
		for (index = 0; index < sizeof(exact_inputs)/sizeof(exact_inputs[0]); index++) {
			long result;
			long long long_result;
			if (feclearexcept(FE_ALL_EXCEPT) != 0) return -1;
			result = direct_lrintl(exact_inputs[index]);
			if (emit_integer(ID_LRINTL, (uint16_t)index,
				rounding_modes[mode], result) != 0) return -1;
			if (feclearexcept(FE_ALL_EXCEPT) != 0) return -1;
			long_result = direct_llrintl(exact_inputs[index]);
			if (emit_integer(ID_LLRINTL, (uint16_t)index,
				rounding_modes[mode], long_result) != 0) return -1;
		}
	}
	return 0;
}

int crabc_x86_64_math_x87_extended_probe(void)
{
#define RUN_UNARY(id, function, inputs) do { \
	if (run_unary((id), (function), (inputs), sizeof(inputs)/sizeof((inputs)[0])) != 0) \
		return (id); \
} while (0)
	RUN_UNARY(ID_ACOSL, direct_acosl, inverse_inputs);
	RUN_UNARY(ID_ASINL, direct_asinl, inverse_inputs);
	RUN_UNARY(ID_ATANL, direct_atanl, inverse_inputs);
	if (run_binary(ID_ATAN2L, direct_atan2l, atan2_inputs,
		sizeof(atan2_inputs)/sizeof(atan2_inputs[0])) != 0) return ID_ATAN2L;
	RUN_UNARY(ID_CEILL, direct_ceill, exact_inputs);
	RUN_UNARY(ID_EXP2L, direct_exp2l, exponential_inputs);
	RUN_UNARY(ID_EXPL, direct_expl, exponential_inputs);
	RUN_UNARY(ID_EXPM1L, direct_expm1l, exponential_inputs);
	RUN_UNARY(ID_FABSL, direct_fabsl, exact_inputs);
	RUN_UNARY(ID_FLOORL, direct_floorl, exact_inputs);
	if (run_binary(ID_FMODL, direct_fmodl, remainder_inputs,
		sizeof(remainder_inputs)/sizeof(remainder_inputs[0])) != 0) return ID_FMODL;
	RUN_UNARY(ID_LOG10L, direct_log10l, logarithm_inputs);
	RUN_UNARY(ID_LOG1PL, direct_log1pl, logarithm_inputs);
	RUN_UNARY(ID_LOG2L, direct_log2l, logarithm_inputs);
	RUN_UNARY(ID_LOGL, direct_logl, logarithm_inputs);
	if (run_integer_conversions() != 0) return ID_LRINTL;
	RUN_UNARY(ID_RINTL, direct_rintl, exact_inputs);
	if (run_binary(ID_REMAINDERL, direct_remainderl, remainder_inputs,
		sizeof(remainder_inputs)/sizeof(remainder_inputs[0])) != 0) return ID_REMAINDERL;
	if (run_remquo() != 0) return ID_REMQUOL;
	RUN_UNARY(ID_SQRTL, direct_sqrtl, sqrt_inputs);
	RUN_UNARY(ID_TRUNCL, direct_truncl, exact_inputs);
	if (fesetround(FE_TONEAREST) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 100;
	return 0;
#undef RUN_UNARY
}

#ifndef CRABC_MATH_X87_EXTENDED_FREESTANDING
int main(void) { return crabc_x86_64_math_x87_extended_probe(); }
#endif
