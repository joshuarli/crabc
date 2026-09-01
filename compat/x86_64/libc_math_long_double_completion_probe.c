/*
 * Native Linux/x86-64 binary80 fdiml/exp10l/pow10l differential.
 *
 * This fixture deliberately keeps two kinds of evidence separate:
 *
 * - `verify_binary80_abi` is a local SysV AMD64 ABI/layout assertion.  It
 *   checks the C representation contract and makes typed indirect calls whose
 *   ten defined binary80 bytes must be exact.  It does not compare padding,
 *   which is not part of the long-double value ABI.
 * - the record stream is a pinned-musl behavioral differential.  It compares
 *   fdiml's NaN/zero/subtraction paths and exp10l/pow10l's table, fractional,
 *   powl fallback, underflow, overflow, and alias paths in all four rounding
 *   modes. Each record retains independently observed x87 and MXCSR state,
 *   including the complete control snapshots immediately around every named
 *   call. `exp10l` temporarily changes the x87 control word to convert its
 *   table index, so restoring the caller's entire control state is part of
 *   this narrow binary80 ABI contract.
 *
 * The surrounding runner compiles this unchanged source first with the
 * pinned musl 1.2.6 oracle and then against the feature-gated crabc archive.
 * It therefore must not be treated as a general libm, fenv, runtime, or
 * public-support claim.
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

_Static_assert(sizeof(long double) == 16, "SysV AMD64 binary80 storage");
_Static_assert(_Alignof(long double) == 16, "SysV AMD64 binary80 alignment");
_Static_assert(LDBL_MANT_DIG == 64, "SysV AMD64 binary80 precision");
_Static_assert(LDBL_MAX_EXP == 16384, "SysV AMD64 binary80 maximum exponent");
_Static_assert(LDBL_MIN_EXP == -16381, "SysV AMD64 binary80 minimum exponent");

typedef long double (*unary_long_double_function)(long double);
typedef long double (*binary_long_double_function)(long double, long double);

/* Parentheses force typed C-ABI calls rather than a compiler builtin. */
static binary_long_double_function volatile direct_fdiml = (fdiml);
static unary_long_double_function volatile direct_exp10l = (exp10l);
static unary_long_double_function volatile direct_pow10l = (pow10l);

enum function_id {
	ID_BINARY80_ABI = 1,
	ID_FDIML = 2,
	ID_EXP10L = 3,
	ID_POW10L = 4,
};

enum {
	FDIM_CASES = 13,
	EXP10_CASES = 24,
	ROUNDING_CASES = 4,
};

/*
 * The first ten bytes are the defined little-endian binary80 payload.  The
 * trailing six SysV storage bytes are deliberately never read or emitted.
 */
union long_double_bits {
	long double value;
	struct {
		uint64_t mantissa;
		uint16_t sign_exponent;
		unsigned char padding[6];
	} fields;
	unsigned char bytes[16];
};

_Static_assert(offsetof(union long_double_bits, fields.mantissa) == 0,
	"binary80 mantissa offset");
_Static_assert(offsetof(union long_double_bits, fields.sign_exponent) == 8,
	"binary80 sign/exponent offset");

/* Stable raw record format consumed by validate_libc_math_long_double_completion.py. */
struct __attribute__((packed)) result_record {
	uint16_t function;
	uint16_t case_index;
	uint32_t requested_rounding;
	uint16_t x87_rounding;
	uint16_t x87_exceptions;
	uint16_t mxcsr_rounding;
	uint16_t mxcsr_exceptions;
	uint32_t combined_exceptions;
	unsigned char value[10];
	uint16_t x87_control_before;
	uint16_t x87_control_after;
	uint32_t mxcsr_control_before;
	uint32_t mxcsr_control_after;
};

_Static_assert(sizeof(struct result_record) == 42, "stable binary80 record");

static const int rounding_modes[ROUNDING_CASES] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

static uint16_t x87_control_word(void)
{
	uint16_t value;
	__asm__ volatile ("fnstcw %0" : "=m" (value) : : "memory");
	return value;
}

static uint16_t x87_status_word(void)
{
	uint16_t value;
	__asm__ volatile ("fnstsw %0" : "=m" (value) : : "memory");
	return value;
}

static uint32_t mxcsr_word(void)
{
	uint32_t value;
	__asm__ volatile ("stmxcsr %0" : "=m" (value) : : "memory");
	return value;
}

/* Sticky exception flags occupy MXCSR bits 0..5; every remaining control
 * bit (DAZ, masks, rounding, and FTZ) must survive each binary80 call. */
#define MXCSR_CONTROL_MASK UINT32_C(0xffc0)

struct control_state {
	uint16_t x87_control;
	uint32_t mxcsr;
};

static struct control_state capture_control_state(void)
{
	struct control_state state;

	state.x87_control = x87_control_word();
	state.mxcsr = mxcsr_word();
	return state;
}

static int controls_preserved(struct control_state before,
	struct control_state after)
{
	return before.x87_control == after.x87_control &&
		(before.mxcsr & MXCSR_CONTROL_MASK) ==
			(after.mxcsr & MXCSR_CONTROL_MASK);
}

static int complete_controls_restored(struct control_state before,
	struct control_state after)
{
	return before.x87_control == after.x87_control &&
		before.mxcsr == after.mxcsr;
}

static long raw_write(const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;

	while (length != 0) {
		register long number __asm__("rax") = 1;
		register long descriptor __asm__("rdi") = 1;
		register const void *address __asm__("rsi") = cursor;
		register size_t count __asm__("rdx") = length;
		__asm__ volatile ("syscall" : "+a" (number)
			: "D" (descriptor), "S" (address), "d" (count)
			: "rcx", "r11", "memory");
		if (number == -4)
			continue;
		if (number <= 0 || (size_t)number > length)
			return -1;
		cursor += number;
		length -= (size_t)number;
	}
	return 0;
}

static int emit_record(uint16_t function, uint16_t case_index,
	int requested_rounding, long double value, struct control_state before)
{
	struct result_record record;
	union long_double_bits bits;
	struct control_state after;
	uint16_t x87_control;
	uint16_t x87_status;
	uint32_t mxcsr;
	unsigned int index;

	after = capture_control_state();
	if (!controls_preserved(before, after))
		return -1;
	bits.value = value;
	x87_control = x87_control_word();
	x87_status = x87_status_word();
	mxcsr = mxcsr_word();
	record.function = function;
	record.case_index = case_index;
	record.requested_rounding = (uint32_t)requested_rounding;
	record.x87_rounding = x87_control & 0x0c00u;
	record.x87_exceptions = x87_status & FE_ALL_EXCEPT;
	record.mxcsr_rounding = (uint16_t)((mxcsr >> 3) & 0x0c00u);
	record.mxcsr_exceptions = (uint16_t)(mxcsr & FE_ALL_EXCEPT);
	record.combined_exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
	for (index = 0; index < 10; index++)
		record.value[index] = bits.bytes[index];
	record.x87_control_before = before.x87_control;
	record.x87_control_after = after.x87_control;
	record.mxcsr_control_before = before.mxcsr & MXCSR_CONTROL_MASK;
	record.mxcsr_control_after = after.mxcsr & MXCSR_CONTROL_MASK;
	return raw_write(&record, sizeof(record)) == 0 ? 0 : -1;
}

static int defined_bytes_equal(long double value, const unsigned char expected[10])
{
	union long_double_bits bits;
	unsigned int index;

	bits.value = value;
	for (index = 0; index < 10; index++)
		if (bits.bytes[index] != expected[index])
			return 0;
	return 1;
}

static long double binary80_from_parts(uint64_t mantissa, uint16_t sign_exponent)
{
	union long_double_bits bits = { .bytes = { 0 } };

	bits.fields.mantissa = mantissa;
	bits.fields.sign_exponent = sign_exponent;
	return bits.value;
}

static int verify_binary80_abi(void)
{
	static const unsigned char one[10] = {
		0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f,
	};
	static const unsigned char two[10] = {
		0, 0, 0, 0, 0, 0, 0, 0x80, 0x00, 0x40,
	};
	static const unsigned char ten[10] = {
		0, 0, 0, 0, 0, 0, 0, 0xa0, 0x02, 0x40,
	};
	long double result;
	struct control_state before;

	if (!defined_bytes_equal(1.0L, one))
		return 1;
	if (direct_exp10l != direct_pow10l)
		return 2;
	if (fesetround(FE_TONEAREST) != 0 ||
		feclearexcept(FE_ALL_EXCEPT) != 0)
		return 3;
	before = capture_control_state();
	result = direct_fdiml(3.0L, 1.0L);
	if (!defined_bytes_equal(result, two) ||
		emit_record(ID_BINARY80_ABI, 0, FE_TONEAREST, result, before) != 0)
		return 4;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 5;
	before = capture_control_state();
	result = direct_exp10l(1.0L);
	if (!defined_bytes_equal(result, ten) ||
		emit_record(ID_BINARY80_ABI, 1, FE_TONEAREST, result, before) != 0)
		return 6;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 7;
	before = capture_control_state();
	result = direct_pow10l(1.0L);
	if (!defined_bytes_equal(result, ten) ||
		emit_record(ID_BINARY80_ABI, 2, FE_TONEAREST, result, before) != 0)
		return 8;
	return 0;
}

static int fdim_operands(unsigned int index, long double *left, long double *right)
{
	switch (index) {
	case 0: *left = 3.0L; *right = 1.0L; return 0;
	case 1: *left = 1.0L; *right = 3.0L; return 0;
	case 2: *left = -0.0L; *right = 0.0L; return 0;
	case 3: *left = 0.0L; *right = -0.0L; return 0;
	case 4: *left = HUGE_VALL; *right = HUGE_VALL; return 0;
	case 5: *left = HUGE_VALL; *right = 1.0L; return 0;
	case 6: *left = -HUGE_VALL; *right = 1.0L; return 0;
	case 7: *left = binary80_from_parts(UINT64_C(0xc0000000000041), 0x7fff); *right = 1.0L; return 0;
	case 8: *left = 1.0L; *right = binary80_from_parts(UINT64_C(0xc0000000000042), 0x7fff); return 0;
	case 9: *left = binary80_from_parts(UINT64_C(0x8000000000000043), 0x7fff); *right = 1.0L; return 0;
	case 10: *left = 1.0L; *right = binary80_from_parts(UINT64_C(0x8000000000000044), 0x7fff); return 0;
	case 11: *left = 0x1p100L; *right = 0x1p-100L; return 0;
	case 12: *left = LDBL_MAX; *right = -LDBL_MAX; return 0;
	default: return -1;
	}
}

static int exp10_operand(unsigned int index, long double *input)
{
	switch (index) {
	case 0: *input = 0.0L; return 0;
	case 1: *input = -0.0L; return 0;
	case 2: *input = LDBL_TRUE_MIN; return 0;
	case 3: *input = -LDBL_TRUE_MIN; return 0;
	case 4: *input = -15.0L; return 0;
	case 5: *input = -1.0L; return 0;
	case 6: *input = 1.0L; return 0;
	case 7: *input = 15.0L; return 0;
	case 8: *input = 0.5L; return 0;
	case 9: *input = -0.5L; return 0;
	case 10: *input = 15.5L; return 0;
	case 11: *input = -15.5L; return 0;
	case 12: *input = 16.0L; return 0;
	case 13: *input = -16.0L; return 0;
	case 14: *input = 16.5L; return 0;
	case 15: *input = -16.5L; return 0;
	case 16: *input = 4932.0L; return 0;
	case 17: *input = 4933.0L; return 0;
	case 18: *input = -4950.0L; return 0;
	case 19: *input = -4951.0L; return 0;
	case 20: *input = HUGE_VALL; return 0;
	case 21: *input = -HUGE_VALL; return 0;
	case 22: *input = binary80_from_parts(UINT64_C(0xc0000000000045), 0x7fff); return 0;
	case 23: *input = binary80_from_parts(UINT64_C(0x8000000000000046), 0x7fff); return 0;
	default: return -1;
	}
}

static int run_fdiml(void)
{
	unsigned int mode_index;
	unsigned int case_index;

	for (mode_index = 0; mode_index < ROUNDING_CASES; mode_index++) {
		for (case_index = 0; case_index < FDIM_CASES; case_index++) {
			long double left;
			long double right;
			long double result;
			struct control_state before;

			if (fdim_operands(case_index, &left, &right) != 0 ||
				fesetround(rounding_modes[mode_index]) != 0 ||
				feclearexcept(FE_ALL_EXCEPT) != 0)
				return -1;
			before = capture_control_state();
			result = direct_fdiml(left, right);
			if (emit_record(ID_FDIML, (uint16_t)case_index,
				rounding_modes[mode_index], result, before) != 0)
				return -1;
		}
	}
	return 0;
}

static int run_exp10l(uint16_t function, unary_long_double_function operation)
{
	unsigned int mode_index;
	unsigned int case_index;

	for (mode_index = 0; mode_index < ROUNDING_CASES; mode_index++) {
		for (case_index = 0; case_index < EXP10_CASES; case_index++) {
			long double input;
			long double result;
			struct control_state before;

			if (exp10_operand(case_index, &input) != 0 ||
				fesetround(rounding_modes[mode_index]) != 0 ||
				feclearexcept(FE_ALL_EXCEPT) != 0)
				return -1;
			before = capture_control_state();
			result = operation(input);
			if (emit_record(function, (uint16_t)case_index,
				rounding_modes[mode_index], result, before) != 0)
				return -1;
		}
	}
	return 0;
}

int crabc_x86_64_math_long_double_completion_probe(void)
{
	fenv_t original;
	struct control_state original_controls;
	struct control_state restored_controls;
	int status;

	original_controls = capture_control_state();
	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	status = verify_binary80_abi();
	if (status == 0)
		status = run_fdiml();
	if (status == 0)
		status = run_exp10l(ID_EXP10L, direct_exp10l);
	if (status == 0)
		status = run_exp10l(ID_POW10L, direct_pow10l);
	if (fesetenv(&original) != 0) {
		if (status == 0)
			status = 2;
	} else {
		restored_controls = capture_control_state();
		if (status == 0 &&
			!complete_controls_restored(original_controls, restored_controls))
			status = 3;
	}
	return status;
}

#ifndef CRABC_MATH_LONG_DOUBLE_COMPLETION_FREESTANDING
int main(void)
{
	return crabc_x86_64_math_long_double_completion_probe();
}
#endif
