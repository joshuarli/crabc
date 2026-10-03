/*
 * Static Linux/x86-64 fenv-sensitive rounding ABI probe.
 *
 * This fixture selects exactly rint/nearbyint in binary32, binary64, and x87
 * binary80 form.  Each name is called through a function pointer after the
 * same project-header body passes against pinned musl 1.2.6.  rint must obey
 * the relevant MXCSR/x87 rounding field and raise FE_INEXACT for fractional
 * inputs; nearbyint must return the same value without clearing a preexisting
 * FE_INEXACT flag.  This is not an exp10/pow10/fdim, integer-conversion,
 * general elementary-math, or complete math.elementary-fenv-sensitive claim.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <math.h>
#include <stdint.h>

_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16,
	"x86 long-double storage");

typedef double (*double_round_function)(double);
typedef float (*float_round_function)(float);
typedef long double (*long_round_function)(long double);

/* Parentheses force the callable ABI symbols rather than compiler builtins. */
static double_round_function const direct_rint = (rint);
static float_round_function const direct_rintf = (rintf);
static long_round_function const direct_rintl = (rintl);
static double_round_function const direct_nearbyint = (nearbyint);
static float_round_function const direct_nearbyintf = (nearbyintf);
static long_round_function const direct_nearbyintl = (nearbyintl);

static uint64_t double_bits(double value)
{
	union {
		double value;
		uint64_t bits;
	} view = { .value = value };
	return view.bits;
}

static uint32_t float_bits(float value)
{
	union {
		float value;
		uint32_t bits;
	} view = { .value = value };
	return view.bits;
}

static double double_from_bits(uint64_t bits)
{
	union {
		uint64_t bits;
		double value;
	} view = { .bits = bits };
	return view.value;
}

static float float_from_bits(uint32_t bits)
{
	union {
		uint32_t bits;
		float value;
	} view = { .bits = bits };
	return view.value;
}

static int raw_round_state(int mode, uint32_t expected_flags)
{
	uint32_t mxcsr;
	uint16_t x87_status;
	uint16_t x87_control;

	__asm__ volatile ("stmxcsr %0" : "=m"(mxcsr) : : "memory");
	__asm__ volatile ("fnstsw %0" : "=m"(x87_status) : : "memory");
	__asm__ volatile ("fnstcw %0" : "=m"(x87_control) : : "memory");
	return mxcsr == (UINT32_C(0x1f80) | ((uint32_t)mode << 3) |
		expected_flags) && x87_control == (UINT16_C(0x037f) | mode) &&
		(x87_status & FE_ALL_EXCEPT) == 0;
}

static int check_double_edge(double_round_function function, uint64_t input,
	uint64_t expected, int mode, uint32_t expected_flags)
{
	volatile double value = double_from_bits(input);
	double result;

	if (fesetenv(FE_DFL_ENV) != 0 || fesetround(mode) != 0)
		return 0;
	result = function(value);
	return double_bits(result) == expected &&
		raw_round_state(mode, expected_flags);
}

static int check_float_edge(float_round_function function, uint32_t input,
	uint32_t expected, int mode, uint32_t expected_flags)
{
	volatile float value = float_from_bits(input);
	float result;

	if (fesetenv(FE_DFL_ENV) != 0 || fesetround(mode) != 0)
		return 0;
	result = function(value);
	return float_bits(result) == expected &&
		raw_round_state(mode, expected_flags);
}

static int check_raw_rounding_edges(void)
{
	static const int modes[4] = {
		FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
	};
	static const uint64_t positive_double[4] = {
		0, 0, UINT64_C(0x3ff0000000000000), 0,
	};
	static const uint64_t negative_double[4] = {
		UINT64_C(0x8000000000000000), UINT64_C(0xbff0000000000000),
		UINT64_C(0x8000000000000000), UINT64_C(0x8000000000000000),
	};
	static const uint32_t positive_float[4] = {
		0, 0, UINT32_C(0x3f800000), 0,
	};
	static const uint32_t negative_float[4] = {
		UINT32_C(0x80000000), UINT32_C(0xbf800000),
		UINT32_C(0x80000000), UINT32_C(0x80000000),
	};
	int index;

	/* The pinned x86 SSE path reports denormal input in MXCSR even when
	 * nearbyint clears the inexact raised while rounding it to zero. */
	for (index = 0; index < 4; index++) {
		int mode = modes[index];
		if (!check_double_edge(direct_rint, 1, positive_double[index],
				mode, 0x22) ||
			!check_double_edge(direct_nearbyint, 1,
				positive_double[index], mode, 0x02) ||
			!check_double_edge(direct_rint,
				UINT64_C(0x8000000000000001),
				negative_double[index], mode, 0x22) ||
			!check_double_edge(direct_nearbyint,
				UINT64_C(0x8000000000000001),
				negative_double[index], mode, 0x02))
			return 1;
		if (!check_float_edge(direct_rintf, 1, positive_float[index],
				mode, 0x22) ||
			!check_float_edge(direct_nearbyintf, 1,
				positive_float[index], mode, 0x02) ||
			!check_float_edge(direct_rintf, UINT32_C(0x80000001),
				negative_float[index], mode, 0x22) ||
			!check_float_edge(direct_nearbyintf, UINT32_C(0x80000001),
				negative_float[index], mode, 0x02))
			return 2;
		/* Musl's exponent fast path returns signaling NaNs unchanged. No
		 * SSE operation consumes them, so neither unit raises invalid. */
		if (!check_double_edge(direct_rint, UINT64_C(0x7ff0000000000042),
				UINT64_C(0x7ff0000000000042), mode, 0) ||
			!check_double_edge(direct_nearbyint,
				UINT64_C(0x7ff0000000000042),
				UINT64_C(0x7ff0000000000042), mode, 0) ||
			!check_float_edge(direct_rintf, UINT32_C(0x7f800042),
				UINT32_C(0x7f800042), mode, 0) ||
			!check_float_edge(direct_nearbyintf,
				UINT32_C(0x7f800042),
				UINT32_C(0x7f800042), mode, 0))
			return 3;
	}
	return 0;
}

static uint16_t long_sign_exponent(long double value)
{
	union {
		long double value;
		unsigned char raw[16];
	} view = { .value = value };
	return (uint16_t)view.raw[8] | ((uint16_t)view.raw[9] << 8);
}

static int check_long_value(long double value, int expected)
{
	if (expected == 0)
		return value == 0.0L && long_sign_exponent(value) == 0;
	if (expected == -0x10)
		return value == 0.0L && long_sign_exponent(value) == UINT16_C(0x8000);
	return value == (long double)expected;
}

static uint64_t expected_double_bits(int mode_index, int input_index)
{
	static const uint64_t values[4][4] = {
		{ UINT64_C(0), UINT64_C(0x4000000000000000),
		  UINT64_C(0x8000000000000000), UINT64_C(0xc000000000000000) },
		{ UINT64_C(0), UINT64_C(0x3ff0000000000000),
		  UINT64_C(0xbff0000000000000), UINT64_C(0xc000000000000000) },
		{ UINT64_C(0x3ff0000000000000), UINT64_C(0x4000000000000000),
		  UINT64_C(0x8000000000000000), UINT64_C(0xbff0000000000000) },
		{ UINT64_C(0), UINT64_C(0x3ff0000000000000),
		  UINT64_C(0x8000000000000000), UINT64_C(0xbff0000000000000) },
	};
	return values[mode_index][input_index];
}

static uint32_t expected_float_bits(int mode_index, int input_index)
{
	static const uint32_t values[4][4] = {
		{ UINT32_C(0), UINT32_C(0x40000000),
		  UINT32_C(0x80000000), UINT32_C(0xc0000000) },
		{ UINT32_C(0), UINT32_C(0x3f800000),
		  UINT32_C(0xbf800000), UINT32_C(0xc0000000) },
		{ UINT32_C(0x3f800000), UINT32_C(0x40000000),
		  UINT32_C(0x80000000), UINT32_C(0xbf800000) },
		{ UINT32_C(0), UINT32_C(0x3f800000),
		  UINT32_C(0x80000000), UINT32_C(0xbf800000) },
	};
	return values[mode_index][input_index];
}

static int expected_long_value(int mode_index, int input_index)
{
	static const int values[4][4] = {
		{ 0, 2, -0x10, -2 },
		{ 0, 1, -1, -2 },
		{ 1, 2, -0x10, -1 },
		{ 0, 1, -0x10, -1 },
	};
	return values[mode_index][input_index];
}

static int check_binary64_mode(int mode, int mode_index)
{
	volatile double inputs[4] = { 0.5, 1.5, -0.5, -1.5 };
	int index;

	if (fesetround(mode) != 0)
		return 1;
	for (index = 0; index < 4; index++) {
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 2;
		if (double_bits(direct_rint(inputs[index])) !=
			expected_double_bits(mode_index, index))
			return 3 + index;
		if (!(fetestexcept(FE_INEXACT) & FE_INEXACT))
			return 7 + index;
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 11;
		if (double_bits(direct_nearbyint(inputs[index])) !=
			expected_double_bits(mode_index, index))
			return 12 + index;
		if (fetestexcept(FE_ALL_EXCEPT) != 0)
			return 16 + index;
	}
	return 0;
}

static int check_binary32_mode(int mode, int mode_index)
{
	volatile float inputs[4] = { 0.5f, 1.5f, -0.5f, -1.5f };
	int index;

	if (fesetround(mode) != 0)
		return 1;
	for (index = 0; index < 4; index++) {
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 2;
		if (float_bits(direct_rintf(inputs[index])) !=
			expected_float_bits(mode_index, index))
			return 3 + index;
		if (!(fetestexcept(FE_INEXACT) & FE_INEXACT))
			return 7 + index;
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 11;
		if (float_bits(direct_nearbyintf(inputs[index])) !=
			expected_float_bits(mode_index, index))
			return 12 + index;
		if (fetestexcept(FE_ALL_EXCEPT) != 0)
			return 16 + index;
	}
	return 0;
}

static int check_binary80_mode(int mode, int mode_index)
{
	volatile long double inputs[4] = { 0.5L, 1.5L, -0.5L, -1.5L };
	int index;

	if (fesetround(mode) != 0)
		return 1;
	for (index = 0; index < 4; index++) {
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 2;
		if (!check_long_value(direct_rintl(inputs[index]),
			expected_long_value(mode_index, index)))
			return 3 + index;
		if (!(fetestexcept(FE_INEXACT) & FE_INEXACT))
			return 7 + index;
		if (feclearexcept(FE_ALL_EXCEPT) != 0)
			return 11;
		if (!check_long_value(direct_nearbyintl(inputs[index]),
			expected_long_value(mode_index, index)))
			return 12 + index;
		if (fetestexcept(FE_ALL_EXCEPT) != 0)
			return 16 + index;
	}
	return 0;
}

static int check_preserved_exceptions(void)
{
	volatile double d = 1.5;
	volatile float f = 1.5f;
	volatile long double l = 1.5L;

	if (fesetround(FE_TONEAREST) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 1;
	if (feraiseexcept(FE_INEXACT | FE_DIVBYZERO) != 0)
		return 2;
	(void)direct_nearbyint(d);
	(void)direct_nearbyintf(f);
	(void)direct_nearbyintl(l);
	if ((fetestexcept(FE_INEXACT | FE_DIVBYZERO) &
		(FE_INEXACT | FE_DIVBYZERO)) != (FE_INEXACT | FE_DIVBYZERO))
		return 3;
	return 0;
}

static int check_special_values(void)
{
	volatile double negative_zero = -0.0;
	volatile float negative_zerof = -0.0f;
	volatile long double negative_zerol = -0.0L;

	if (double_bits(direct_rint(negative_zero)) != UINT64_C(0x8000000000000000) ||
		double_bits(direct_nearbyint(HUGE_VAL)) != UINT64_C(0x7ff0000000000000) ||
		!isnan(direct_rint(NAN)))
		return 1;
	if (float_bits(direct_rintf(negative_zerof)) != UINT32_C(0x80000000) ||
		float_bits(direct_nearbyintf(HUGE_VALF)) != UINT32_C(0x7f800000) ||
		!isnan(direct_rintf(NAN)))
		return 2;
	if (!check_long_value(direct_rintl(negative_zerol), -0x10) ||
		direct_nearbyintl(HUGE_VALL) != HUGE_VALL ||
		!isnan(direct_rintl((long double)NAN)))
		return 3;
	return 0;
}

/* Write one fixed-width hexadecimal row through the Linux syscall ABI so the
 * same observation code runs in the musl program and the freestanding image. */
static char differential_row[128];
static unsigned differential_length;
static int differential_write_error;

static void put_hex(uint64_t value, unsigned digits)
{
	unsigned start = differential_length;
	differential_length += digits;
	while (digits != 0) {
		digits--;
		differential_row[start + digits] = "0123456789abcdef"[value & 15];
		value >>= 4;
	}
}

static void put_long_bits(long double value)
{
	union {
		long double value;
		unsigned char raw[16];
	} view = { .value = value };
	int index;
	for (index = 9; index >= 0; index--)
		put_hex(view.raw[index], 2);
}

static void finish_row(void)
{
	register long number __asm__("rax") = 1;
	register long descriptor __asm__("rdi") = 1;
	register const char *bytes __asm__("rsi") = differential_row;
	register long count __asm__("rdx") = differential_length;
	differential_row[differential_length++] = '\n';
	count = differential_length;
	__asm__ volatile ("syscall" : "+a"(number) : "D"(descriptor),
		"S"(bytes), "d"(count) : "rcx", "r11", "memory");
	if (number != count)
		differential_write_error = 1;
}

static void begin_row(unsigned precision, unsigned operation, unsigned mode,
	unsigned seed, unsigned input)
{
	/* Identity fields precede result bits, MXCSR, x87 control, and x87 flags. */
	differential_length = 0;
	put_hex(precision, 1);
	put_hex(operation, 1);
	put_hex(mode, 1);
	put_hex(seed, 1);
	put_hex(input, 2);
	differential_row[differential_length++] = ' ';
}

static void put_environment(void)
{
	uint32_t mxcsr;
	uint16_t control;
	uint16_t status;
	__asm__ volatile ("stmxcsr %0" : "=m"(mxcsr) : : "memory");
	__asm__ volatile ("fnstcw %0" : "=m"(control) : : "memory");
	__asm__ volatile ("fnstsw %0" : "=m"(status) : : "memory");
	put_hex(mxcsr, 8);
	put_hex(control, 4);
	put_hex(status & FE_ALL_EXCEPT, 2);
}

static int inexact_matches_input(int operation, int seed, int index)
{
	int exact = index == 0 || index == 1 || index == 8 || index == 9;
	int expected = (seed & FE_INEXACT) != 0 || (!operation && !exact);
	return ((fetestexcept(FE_INEXACT) & FE_INEXACT) != 0) == expected;
}

static int emit_differential(void)
{
	static const int modes[4] = {
		FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
	};
	static const int seeds[4] = {
		0, FE_INEXACT, FE_DIVBYZERO, FE_INEXACT | FE_DIVBYZERO,
	};
	static const uint64_t doubles[] = {
		0, UINT64_C(0x8000000000000000),
		UINT64_C(0x3fe0000000000000), UINT64_C(0xbfe0000000000000),
		UINT64_C(0x3ff8000000000000), UINT64_C(0xbff8000000000000),
		1, UINT64_C(0x8000000000000001),
		UINT64_C(0x3ff0000000000000), UINT64_C(0xbff0000000000000),
		UINT64_C(0x432fffffffffffff), UINT64_C(0xc32fffffffffffff),
	};
	static const uint32_t floats[] = {
		0, UINT32_C(0x80000000),
		UINT32_C(0x3f000000), UINT32_C(0xbf000000),
		UINT32_C(0x3fc00000), UINT32_C(0xbfc00000),
		1, UINT32_C(0x80000001),
		UINT32_C(0x3f800000), UINT32_C(0xbf800000),
		UINT32_C(0x4affffff), UINT32_C(0xcaffffff),
	};
	static const long double longs[] = {
		0.0L, -0.0L, 0.5L, -0.5L, 1.5L, -1.5L,
		0x1p-16445L, -0x1p-16445L, 1.0L, -1.0L,
		0x1.fffffffffffffffep62L, -0x1.fffffffffffffffep62L,
	};
	int mode, seed, operation, index;
	for (mode = 0; mode < 4; mode++)
	for (seed = 0; seed < 4; seed++)
	for (operation = 0; operation < 2; operation++)
	for (index = 0; index < 12; index++) {
		volatile double d = double_from_bits(doubles[index]);
		volatile float f = float_from_bits(floats[index]);
		volatile long double l = longs[index];
		double dr;
		float fr;
		long double lr;
		if (fesetenv(FE_DFL_ENV) != 0 || fesetround(modes[mode]) != 0 ||
			feraiseexcept(seeds[seed]) != 0)
			return 1;
		dr = operation ? direct_nearbyint(d) : direct_rint(d);
		if (!inexact_matches_input(operation, seeds[seed], index))
			return 4;
		begin_row(0, operation, mode, seed, index);
		put_hex(double_bits(dr), 16);
		differential_row[differential_length++] = ' ';
		put_environment();
		finish_row();
		if (fesetenv(FE_DFL_ENV) != 0 || fesetround(modes[mode]) != 0 ||
			feraiseexcept(seeds[seed]) != 0)
			return 2;
		fr = operation ? direct_nearbyintf(f) : direct_rintf(f);
		if (!inexact_matches_input(operation, seeds[seed], index))
			return 5;
		begin_row(1, operation, mode, seed, index);
		put_hex(float_bits(fr), 8);
		differential_row[differential_length++] = ' ';
		put_environment();
		finish_row();
		if (fesetenv(FE_DFL_ENV) != 0 || fesetround(modes[mode]) != 0 ||
			feraiseexcept(seeds[seed]) != 0)
			return 3;
		lr = operation ? direct_nearbyintl(l) : direct_rintl(l);
		if (!inexact_matches_input(operation, seeds[seed], index))
			return 6;
		begin_row(2, operation, mode, seed, index);
		put_long_bits(lr);
		differential_row[differential_length++] = ' ';
		put_environment();
		finish_row();
	}
	return differential_write_error;
}

static int set_split_rounding(int mxcsr_mode, int x87_mode)
{
	uint32_t mxcsr;
	uint16_t control;
	if (fesetenv(FE_DFL_ENV) != 0)
		return 0;
	__asm__ volatile ("stmxcsr %0" : "=m"(mxcsr) : : "memory");
	__asm__ volatile ("fnstcw %0" : "=m"(control) : : "memory");
	mxcsr = (mxcsr & ~UINT32_C(0x6000)) | ((uint32_t)mxcsr_mode << 3);
	control = (uint16_t)((control & ~UINT16_C(0x0c00)) | x87_mode);
	__asm__ volatile ("ldmxcsr %0" : : "m"(mxcsr) : "memory");
	__asm__ volatile ("fldcw %0" : : "m"(control) : "memory");
	return 1;
}

/* Opposite unit modes prove that binary32/64 use MXCSR while binary80 uses
 * the x87 control word, beyond observing that fesetround updates both. */
static int check_split_rounding(void)
{
	static const int mxcsr_modes[2] = { FE_UPWARD, FE_DOWNWARD };
	static const int x87_modes[2] = { FE_DOWNWARD, FE_UPWARD };
	static const uint64_t double_results[2][2] = {
		{ UINT64_C(0x3ff0000000000000), UINT64_C(0x8000000000000000) },
		{ 0, UINT64_C(0xbff0000000000000) },
	};
	static const uint32_t float_results[2][2] = {
		{ UINT32_C(0x3f800000), UINT32_C(0x80000000) },
		{ 0, UINT32_C(0xbf800000) },
	};
	static const int long_results[2][2] = {
		{ 0, -1 }, { 1, -0x10 },
	};
	int selection, sign, operation;
	for (selection = 0; selection < 2; selection++)
	for (sign = 0; sign < 2; sign++)
	for (operation = 0; operation < 2; operation++) {
		volatile double d = sign ? -0.5 : 0.5;
		volatile float f = sign ? -0.5f : 0.5f;
		volatile long double l = sign ? -0.5L : 0.5L;
		double dr;
		float fr;
		long double lr;
		if (!set_split_rounding(mxcsr_modes[selection], x87_modes[selection]))
			return 1;
		dr = operation ? direct_nearbyint(d) : direct_rint(d);
		if (double_bits(dr) != double_results[selection][sign])
			return 2;
		begin_row(0, operation, 4 + selection, 0, sign);
		put_hex(double_bits(dr), 16);
		differential_row[differential_length++] = ' ';
		put_environment();
		finish_row();
		if (!set_split_rounding(mxcsr_modes[selection], x87_modes[selection]))
			return 3;
		fr = operation ? direct_nearbyintf(f) : direct_rintf(f);
		if (float_bits(fr) != float_results[selection][sign])
			return 4;
		begin_row(1, operation, 4 + selection, 0, sign);
		put_hex(float_bits(fr), 8);
		differential_row[differential_length++] = ' ';
		put_environment();
		finish_row();
		if (!set_split_rounding(mxcsr_modes[selection], x87_modes[selection]))
			return 5;
		lr = operation ? direct_nearbyintl(l) : direct_rintl(l);
		if (!check_long_value(lr, long_results[selection][sign]))
			return 6;
		begin_row(2, operation, 4 + selection, 0, sign);
		put_long_bits(lr);
		differential_row[differential_length++] = ' ';
		put_environment();
		finish_row();
	}
	return differential_write_error;
}

/* A saved environment retains each unit's rounding field and exception
 * flags. Exercise the snapshot across hold/update and default restoration,
 * then consume both the SSE scalar and binary80 callable return ABIs. */
static int check_environment_lifetime(void)
{
	int iteration;
	for (iteration = 0; iteration < 8; iteration++) {
		fenv_t held;
		fenv_t restored;
		volatile long double fraction = 1.5L;
		volatile double scalar = 1.5;
		if (!set_split_rounding(FE_UPWARD, FE_DOWNWARD))
			return 1;
		if (direct_rintl(fraction) != 1.0L ||
			feraiseexcept(FE_DIVBYZERO) != 0)
			return 2;
		if (feholdexcept(&held) != 0 ||
			(held.__status_word & FE_INEXACT) == 0 ||
			(held.__mxcsr & FE_DIVBYZERO) == 0 ||
			fetestexcept(FE_ALL_EXCEPT) != 0)
			return 3;
		if (fesetround(FE_TONEAREST) != 0 ||
			direct_rintl(fraction) != 2.0L ||
			feraiseexcept(FE_OVERFLOW) != 0 ||
			feupdateenv(&held) != 0 || fegetenv(&restored) != 0)
			return 4;
		if ((restored.__control_word & 0x0c00) != FE_DOWNWARD ||
			((restored.__mxcsr >> 3) & 0x0c00) != FE_UPWARD ||
			(restored.__status_word & FE_ALL_EXCEPT) != FE_INEXACT ||
			(restored.__mxcsr & FE_ALL_EXCEPT) !=
				(FE_DIVBYZERO | FE_OVERFLOW | FE_INEXACT))
			return 5;
		if (direct_rintl(fraction) != 1.0L || direct_rint(scalar) != 2.0)
			return 6;
		if (feupdateenv(FE_DFL_ENV) != 0 || fegetround() != FE_TONEAREST ||
			fetestexcept(FE_ALL_EXCEPT) !=
				(FE_DIVBYZERO | FE_OVERFLOW | FE_INEXACT))
			return 7;
		if (fesetenv(FE_DFL_ENV) != 0 ||
			!raw_round_state(FE_TONEAREST, 0))
			return 8;
		if (fesetenv(&held) != 0 || direct_nearbyintl(fraction) != 1.0L ||
			direct_nearbyint(scalar) != 2.0 ||
			fetestexcept(FE_ALL_EXCEPT) != (FE_DIVBYZERO | FE_INEXACT))
			return 9;
	}
	return 0;
}

int crabc_x86_64_fenv_rounding_probe(void)
{
	static const int modes[4] = {
		FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
	};
	fenv_t original;
	int mode_index;
	int status = 0;

	if (fegetenv(&original) != 0 || fesetenv(FE_DFL_ENV) != 0)
		return 1;
	for (mode_index = 0; mode_index < 4 && status == 0; mode_index++) {
		status = check_binary64_mode(modes[mode_index], mode_index);
		if (status != 0)
			status += 10 + mode_index * 20;
		else {
			status = check_binary32_mode(modes[mode_index], mode_index);
			if (status != 0)
				status += 100 + mode_index * 20;
		}
		if (status == 0) {
			status = check_binary80_mode(modes[mode_index], mode_index);
			if (status != 0)
				status += 190 + mode_index * 20;
		}
	}
	if (status == 0)
		status = check_preserved_exceptions() == 0 ? 0 : 2;
	if (status == 0)
		status = check_special_values() == 0 ? 0 : 3;
	if (status == 0)
		status = check_raw_rounding_edges() == 0 ? 0 : 5;
	if (status == 0)
		status = emit_differential() == 0 ? 0 : 6;
	if (status == 0)
		status = check_split_rounding() == 0 ? 0 : 7;
	if (status == 0)
		status = check_environment_lifetime() == 0 ? 0 : 8;
	if (fesetenv(&original) != 0 && status == 0)
		status = 4;
	return status;
}

#ifndef CRABC_FENV_ROUNDING_FREESTANDING
int main(void)
{
	return crabc_x86_64_fenv_rounding_probe();
}
#endif
