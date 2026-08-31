/*
 * Native Linux/x86-64 differential for the complete math.special capability.
 *
 * Every named function is called through its project-header function-pointer
 * type. Records contain exact binary32/binary64 payloads, the defined ten
 * bytes of binary80, integer/pointer outputs, and combined x87/MXCSR flags.
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
_Static_assert(sizeof(long) == 8 && sizeof(long long) == 8, "x86 LP64 integers");

typedef double (*d_unary)(double);
typedef float (*f_unary)(float);
typedef long double (*l_unary)(long double);
typedef double (*d_binary)(double, double);
typedef float (*f_binary)(float, float);
typedef long double (*l_binary)(long double, long double);
typedef int (*d_integer)(double);
typedef int (*f_integer)(float);
typedef int (*l_integer)(long double);
typedef double (*d_frexp)(double, int *);
typedef float (*f_frexp)(float, int *);
typedef long double (*l_frexp)(long double, int *);
typedef double (*d_modf)(double, double *);
typedef float (*f_modf)(float, float *);
typedef long double (*l_modf)(long double, long double *);
typedef double (*d_remquo)(double, double, int *);
typedef float (*f_remquo)(float, float, int *);
typedef long double (*l_remquo)(long double, long double, int *);
typedef double (*d_int_scale)(double, int);
typedef float (*f_int_scale)(float, int);
typedef long double (*l_int_scale)(long double, int);
typedef double (*d_long_scale)(double, long);
typedef float (*f_long_scale)(float, long);
typedef long double (*l_long_scale)(long double, long);
typedef long (*d_long)(double);
typedef long (*f_long)(float);
typedef long (*l_long)(long double);
typedef long long (*d_long_long)(double);
typedef long long (*f_long_long)(float);
typedef long long (*l_long_long)(long double);
typedef double (*d_order)(int, double);
typedef float (*f_order)(int, float);
typedef double (*d_nexttoward)(double, long double);
typedef float (*f_nexttoward)(float, long double);
typedef double (*d_gamma_r)(double, int *);
typedef float (*f_gamma_r)(float, int *);
typedef long double (*l_gamma_r)(long double, int *);
typedef double (*d_nan)(const char *);
typedef float (*f_nan)(const char *);
typedef long double (*l_nan)(const char *);

extern long double __lgammal_r(long double, int *);

#define DIRECT(type, name) static type direct_##name = (name)
DIRECT(d_integer, __fpclassify);
DIRECT(f_integer, __fpclassifyf);
DIRECT(l_integer, __fpclassifyl);
DIRECT(l_gamma_r, __lgammal_r);
DIRECT(d_integer, __signbit);
DIRECT(f_integer, __signbitf);
DIRECT(l_integer, __signbitl);
DIRECT(d_binary, drem);
DIRECT(f_binary, dremf);
DIRECT(d_unary, erf);
DIRECT(d_unary, erfc);
DIRECT(f_unary, erfcf);
DIRECT(l_unary, erfcl);
DIRECT(f_unary, erff);
DIRECT(l_unary, erfl);
DIRECT(d_integer, finite);
DIRECT(f_integer, finitef);
DIRECT(d_frexp, frexp);
DIRECT(f_frexp, frexpf);
DIRECT(l_frexp, frexpl);
DIRECT(d_integer, ilogb);
DIRECT(f_integer, ilogbf);
DIRECT(l_integer, ilogbl);
DIRECT(d_unary, j0);
DIRECT(f_unary, j0f);
DIRECT(d_unary, j1);
DIRECT(f_unary, j1f);
DIRECT(d_order, jn);
DIRECT(f_order, jnf);
DIRECT(d_int_scale, ldexp);
DIRECT(f_int_scale, ldexpf);
DIRECT(l_int_scale, ldexpl);
DIRECT(d_unary, lgamma);
DIRECT(d_gamma_r, lgamma_r);
DIRECT(f_unary, lgammaf);
DIRECT(f_gamma_r, lgammaf_r);
DIRECT(l_unary, lgammal);
DIRECT(l_gamma_r, lgammal_r);
DIRECT(d_long_long, llrint);
DIRECT(f_long_long, llrintf);
DIRECT(l_long_long, llrintl);
DIRECT(d_long_long, llround);
DIRECT(f_long_long, llroundf);
DIRECT(l_long_long, llroundl);
DIRECT(d_unary, logb);
DIRECT(f_unary, logbf);
DIRECT(l_unary, logbl);
DIRECT(d_long, lrint);
DIRECT(f_long, lrintf);
DIRECT(l_long, lrintl);
DIRECT(d_long, lround);
DIRECT(f_long, lroundf);
DIRECT(l_long, lroundl);
DIRECT(d_modf, modf);
DIRECT(f_modf, modff);
DIRECT(l_modf, modfl);
DIRECT(d_nan, nan);
DIRECT(f_nan, nanf);
DIRECT(l_nan, nanl);
DIRECT(d_binary, nextafter);
DIRECT(f_binary, nextafterf);
DIRECT(l_binary, nextafterl);
DIRECT(d_nexttoward, nexttoward);
DIRECT(f_nexttoward, nexttowardf);
DIRECT(l_binary, nexttowardl);
DIRECT(d_binary, remainder);
DIRECT(f_binary, remainderf);
DIRECT(l_binary, remainderl);
DIRECT(d_remquo, remquo);
DIRECT(f_remquo, remquof);
DIRECT(l_remquo, remquol);
DIRECT(d_binary, scalb);
DIRECT(f_binary, scalbf);
DIRECT(d_long_scale, scalbln);
DIRECT(f_long_scale, scalblnf);
DIRECT(l_long_scale, scalblnl);
DIRECT(d_int_scale, scalbn);
DIRECT(f_int_scale, scalbnf);
DIRECT(l_int_scale, scalbnl);
DIRECT(d_unary, significand);
DIRECT(f_unary, significandf);
DIRECT(d_unary, tgamma);
DIRECT(f_unary, tgammaf);
DIRECT(l_unary, tgammal);
DIRECT(d_unary, y0);
DIRECT(f_unary, y0f);
DIRECT(d_unary, y1);
DIRECT(f_unary, y1f);
DIRECT(d_order, yn);
DIRECT(f_order, ynf);
#undef DIRECT

extern int __signgam;

enum function_id {
	ID_FPCLASSIFY = 1, ID_FPCLASSIFYF, ID_FPCLASSIFYL, ID_LGAMMAL_INTERNAL_R,
	ID_SIGNBIT, ID_SIGNBITF, ID_SIGNBITL, ID_DREM, ID_DREMF, ID_ERF,
	ID_ERFC, ID_ERFCF, ID_ERFCL, ID_ERFF, ID_ERFL, ID_FINITE, ID_FINITEF,
	ID_FREXP, ID_FREXPF, ID_FREXPL, ID_ILOGB, ID_ILOGBF, ID_ILOGBL,
	ID_J0, ID_J0F, ID_J1, ID_J1F, ID_JN, ID_JNF, ID_LDEXP, ID_LDEXPF,
	ID_LDEXPL, ID_LGAMMA, ID_LGAMMA_R, ID_LGAMMAF, ID_LGAMMAF_R,
	ID_LGAMMAL, ID_LGAMMAL_R, ID_LLRINT, ID_LLRINTF, ID_LLRINTL,
	ID_LLROUND, ID_LLROUNDF, ID_LLROUNDL, ID_LOGB, ID_LOGBF, ID_LOGBL,
	ID_LRINT, ID_LRINTF, ID_LRINTL, ID_LROUND, ID_LROUNDF, ID_LROUNDL,
	ID_MODF, ID_MODFF, ID_MODFL, ID_NAN, ID_NANF, ID_NANL, ID_NEXTAFTER,
	ID_NEXTAFTERF, ID_NEXTAFTERL, ID_NEXTTOWARD, ID_NEXTTOWARDF,
	ID_NEXTTOWARDL, ID_REMAINDER, ID_REMAINDERF, ID_REMAINDERL, ID_REMQUO,
	ID_REMQUOF, ID_REMQUOL, ID_SCALB, ID_SCALBF, ID_SCALBLN, ID_SCALBLNF,
	ID_SCALBLNL, ID_SCALBN, ID_SCALBNF, ID_SCALBNL, ID_SIGNIFICAND,
	ID_SIGNIFICANDF, ID_TGAMMA, ID_TGAMMAF, ID_TGAMMAL, ID_Y0, ID_Y0F,
	ID_Y1, ID_Y1F, ID_YN, ID_YNF,
};

struct __attribute__((packed)) result_record {
	uint16_t function;
	uint16_t case_index;
	uint32_t rounding;
	uint32_t exceptions;
	int32_t auxiliary;
	unsigned char value[16];
};
_Static_assert(sizeof(struct result_record) == 32, "stable result record");

struct d_pair { double left; double right; };
struct f_pair { float left; float right; };
struct l_pair { long double left; long double right; };
struct d_int_pair { double value; int exponent; };
struct f_int_pair { float value; int exponent; };
struct l_int_pair { long double value; int exponent; };
struct d_long_pair { double value; long exponent; };
struct f_long_pair { float value; long exponent; };
struct l_long_pair { long double value; long exponent; };
struct d_order_input { int order; double value; };
struct f_order_input { int order; float value; };
struct d_toward_input { double value; long double toward; };
struct f_toward_input { float value; long double toward; };

static const int rounding_modes[] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};
static const double d_values[] = {
	-INFINITY, -DBL_MAX, -3.5, -2.0, -1.0, -0.5, -DBL_TRUE_MIN, -0.0,
	0.0, DBL_TRUE_MIN, DBL_MIN, 0.5, 1.0, 1.5, 2.0, 8.0, DBL_MAX,
	INFINITY, __builtin_nan("0x1234"),
};
static const float f_values[] = {
	-INFINITY, -FLT_MAX, -3.5f, -2.0f, -1.0f, -0.5f, -FLT_TRUE_MIN, -0.0f,
	0.0f, FLT_TRUE_MIN, FLT_MIN, 0.5f, 1.0f, 1.5f, 2.0f, 8.0f, FLT_MAX,
	INFINITY, __builtin_nanf("0x123"),
};
static const long double l_values[] = {
	-INFINITY, -LDBL_MAX, -3.5L, -2.0L, -1.0L, -0.5L, -LDBL_TRUE_MIN,
	-0.0L, 0.0L, LDBL_TRUE_MIN, LDBL_MIN, 0.5L, 1.0L, 1.5L, 2.0L,
	8.0L, LDBL_MAX, INFINITY, __builtin_nanl("0x1234"),
};
static const double d_special[] = {
	-INFINITY, -10.5, -3.0, -2.5, -1.0, -0.0, 0.0, DBL_TRUE_MIN,
	0.25, 0.5, 1.0, 1.5, 2.0, 6.0, 20.0, 172.0, INFINITY,
	__builtin_nan("0x1234"),
};
static const float f_special[] = {
	-INFINITY, -10.5f, -3.0f, -2.5f, -1.0f, -0.0f, 0.0f, FLT_TRUE_MIN,
	0.25f, 0.5f, 1.0f, 1.5f, 2.0f, 6.0f, 20.0f, 36.0f, INFINITY,
	__builtin_nanf("0x123"),
};
static const long double l_special[] = {
	-INFINITY, -10.5L, -3.0L, -2.5L, -1.0L, -0.0L, 0.0L,
	LDBL_TRUE_MIN, 0.25L, 0.5L, 1.0L, 1.5L, 2.0L, 6.0L, 20.0L,
	1756.0L, INFINITY, __builtin_nanl("0x1234"),
};
static const double d_bessel[] = {
	-INFINITY, -10.0, -2.0, -0.0, 0.0, DBL_TRUE_MIN, 0.5, 1.0, 2.0,
	8.0, 100.0, INFINITY, __builtin_nan("0x1234"),
};
static const float f_bessel[] = {
	-INFINITY, -10.0f, -2.0f, -0.0f, 0.0f, FLT_TRUE_MIN, 0.5f, 1.0f,
	2.0f, 8.0f, 100.0f, INFINITY, __builtin_nanf("0x123"),
};
static const struct d_pair d_pairs[] = {
	{-7.0, 2.0}, {-5.0, 2.0}, {-0.0, 2.0}, {0.0, 2.0}, {5.0, 2.0},
	{7.0, 2.0}, {DBL_MAX, 3.0}, {DBL_TRUE_MIN, 2.0}, {1.0, 0.0},
	{INFINITY, 2.0}, {2.0, INFINITY}, {__builtin_nan("0x1234"), 2.0},
};
static const struct f_pair f_pairs[] = {
	{-7.0f, 2.0f}, {-5.0f, 2.0f}, {-0.0f, 2.0f}, {0.0f, 2.0f},
	{5.0f, 2.0f}, {7.0f, 2.0f}, {FLT_MAX, 3.0f}, {FLT_TRUE_MIN, 2.0f},
	{1.0f, 0.0f}, {INFINITY, 2.0f}, {2.0f, INFINITY},
	{__builtin_nanf("0x123"), 2.0f},
};
static const struct l_pair l_pairs[] = {
	{-7.0L, 2.0L}, {-5.0L, 2.0L}, {-0.0L, 2.0L}, {0.0L, 2.0L},
	{5.0L, 2.0L}, {7.0L, 2.0L}, {LDBL_MAX, 3.0L},
	{LDBL_TRUE_MIN, 2.0L}, {1.0L, 0.0L}, {INFINITY, 2.0L},
	{2.0L, INFINITY}, {__builtin_nanl("0x1234"), 2.0L},
};
static const struct d_pair d_next[] = {
	{-0.0, 0.0}, {0.0, -0.0}, {0.0, 1.0}, {0.0, -1.0},
	{DBL_TRUE_MIN, 0.0}, {DBL_MIN, 0.0}, {1.0, 2.0}, {1.0, 0.0},
	{DBL_MAX, INFINITY}, {INFINITY, 0.0}, {__builtin_nan("0x1234"), 1.0},
};
static const struct f_pair f_next[] = {
	{-0.0f, 0.0f}, {0.0f, -0.0f}, {0.0f, 1.0f}, {0.0f, -1.0f},
	{FLT_TRUE_MIN, 0.0f}, {FLT_MIN, 0.0f}, {1.0f, 2.0f}, {1.0f, 0.0f},
	{FLT_MAX, INFINITY}, {INFINITY, 0.0f}, {__builtin_nanf("0x123"), 1.0f},
};
static const struct l_pair l_next[] = {
	{-0.0L, 0.0L}, {0.0L, -0.0L}, {0.0L, 1.0L}, {0.0L, -1.0L},
	{LDBL_TRUE_MIN, 0.0L}, {LDBL_MIN, 0.0L}, {1.0L, 2.0L},
	{1.0L, 0.0L}, {LDBL_MAX, INFINITY}, {INFINITY, 0.0L},
	{__builtin_nanl("0x1234"), 1.0L},
};
static const struct d_int_pair d_scales[] = {
	{0.0, -1075}, {-0.0, 10}, {DBL_TRUE_MIN, 1}, {1.0, -1074},
	{1.5, -10}, {-1.5, 10}, {DBL_MAX, 1}, {INFINITY, -10},
	{__builtin_nan("0x1234"), 10},
};
static const struct f_int_pair f_scales[] = {
	{0.0f, -150}, {-0.0f, 10}, {FLT_TRUE_MIN, 1}, {1.0f, -149},
	{1.5f, -10}, {-1.5f, 10}, {FLT_MAX, 1}, {INFINITY, -10},
	{__builtin_nanf("0x123"), 10},
};
static const struct l_int_pair l_scales[] = {
	{0.0L, -16446}, {-0.0L, 10}, {LDBL_TRUE_MIN, 1}, {1.0L, -16445},
	{1.5L, -10}, {-1.5L, 10}, {LDBL_MAX, 1}, {INFINITY, -10},
	{__builtin_nanl("0x1234"), 10},
};
static const struct d_long_pair d_long_scales[] = {
	{1.0, -1074L}, {1.5, -10L}, {-1.5, 10L}, {DBL_MAX, 100000L},
	{DBL_TRUE_MIN, -100000L},
};
static const struct f_long_pair f_long_scales[] = {
	{1.0f, -149L}, {1.5f, -10L}, {-1.5f, 10L}, {FLT_MAX, 100000L},
	{FLT_TRUE_MIN, -100000L},
};
static const struct l_long_pair l_long_scales[] = {
	{1.0L, -16445L}, {1.5L, -10L}, {-1.5L, 10L},
	{LDBL_MAX, 100000L}, {LDBL_TRUE_MIN, -100000L},
};
static const struct d_pair d_scalb_pairs[] = {
	{1.0, 3.0}, {-1.5, -3.0}, {DBL_TRUE_MIN, 1.0}, {DBL_MAX, 1.0},
	{1.0, 0.5}, {0.0, INFINITY}, {INFINITY, -INFINITY},
	{__builtin_nan("0x1234"), 2.0},
};
static const struct f_pair f_scalb_pairs[] = {
	{1.0f, 3.0f}, {-1.5f, -3.0f}, {FLT_TRUE_MIN, 1.0f},
	{FLT_MAX, 1.0f}, {1.0f, 0.5f}, {0.0f, INFINITY},
	{INFINITY, -INFINITY}, {__builtin_nanf("0x123"), 2.0f},
};
static const struct d_order_input d_orders[] = {
	{0, 0.5}, {1, 0.5}, {2, 0.5}, {3, 2.0}, {-3, 2.0}, {10, 20.0},
	{100, 1.0}, {-100, 2.0}, {3, INFINITY},
};
static const struct f_order_input f_orders[] = {
	{0, 0.5f}, {1, 0.5f}, {2, 0.5f}, {3, 2.0f}, {-3, 2.0f},
	{10, 20.0f}, {100, 1.0f}, {-100, 2.0f}, {3, INFINITY},
};
static const struct d_toward_input d_toward[] = {
	{-0.0, 0.0L}, {0.0, -0.0L}, {0.0, LDBL_TRUE_MIN},
	{0.0, -LDBL_TRUE_MIN}, {1.0, 1.0L + 0x1p-63L},
	{1.0, 1.0L - 0x1p-63L}, {DBL_MAX, INFINITY}, {INFINITY, 0.0L},
	{__builtin_nan("0x1234"), 1.0L},
};
static const struct f_toward_input f_toward[] = {
	{-0.0f, 0.0L}, {0.0f, -0.0L}, {0.0f, LDBL_TRUE_MIN},
	{0.0f, -LDBL_TRUE_MIN}, {1.0f, 1.0L + 0x1p-40L},
	{1.0f, 1.0L - 0x1p-40L}, {FLT_MAX, INFINITY}, {INFINITY, 0.0L},
	{__builtin_nanf("0x123"), 1.0L},
};
static const char *const nan_tags[] = { "", "1", "0x1234", "invalid" };

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
	for (index = 0; index < 16; index++) destination[index] = 0;
	for (index = 0; index < count; index++) destination[index] = source[index];
}

static int emit_record(uint16_t function, uint16_t case_index, int rounding,
	int auxiliary, const unsigned char *value, size_t value_size)
{
	struct result_record record;
	record.function = function;
	record.case_index = case_index;
	record.rounding = (uint32_t)rounding;
	record.exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
	record.auxiliary = auxiliary;
	copy_bytes(record.value, value, value_size);
	return raw_write(&record, sizeof(record)) == 0 ? 0 : -1;
}

static int emit_double(uint16_t id, uint16_t index, int mode, int auxiliary,
	double value)
{
	union { double value; unsigned char bytes[8]; } bits = { value };
	return emit_record(id, index, mode, auxiliary, bits.bytes, 8);
}

static int emit_float(uint16_t id, uint16_t index, int mode, int auxiliary,
	float value)
{
	union { float value; unsigned char bytes[4]; } bits = { value };
	return emit_record(id, index, mode, auxiliary, bits.bytes, 4);
}

static int emit_long_double(uint16_t id, uint16_t index, int mode, int auxiliary,
	long double value)
{
	union { long double value; unsigned char bytes[16]; } bits = { value };
	return emit_record(id, index, mode, auxiliary, bits.bytes, 10);
}

static int emit_integer(uint16_t id, uint16_t index, int mode, long long value)
{
	union { long long value; unsigned char bytes[8]; } bits = { value };
	return emit_record(id, index, mode, 0, bits.bytes, 8);
}

#define CLEAR() do { if (feclearexcept(FE_ALL_EXCEPT) != 0) return -1; } while (0)
#define RUN_D_UNARY(id, operation, inputs) do { \
	size_t i; for (i = 0; i < sizeof(inputs)/sizeof((inputs)[0]); i++) { \
		double result; CLEAR(); result = (operation)((inputs)[i]); \
		if (emit_double((id), (uint16_t)i, mode, 0, result) != 0) return -1; \
	} \
} while (0)
#define RUN_F_UNARY(id, operation, inputs) do { \
	size_t i; for (i = 0; i < sizeof(inputs)/sizeof((inputs)[0]); i++) { \
		float result; CLEAR(); result = (operation)((inputs)[i]); \
		if (emit_float((id), (uint16_t)i, mode, 0, result) != 0) return -1; \
	} \
} while (0)
#define RUN_L_UNARY(id, operation, inputs) do { \
	size_t i; for (i = 0; i < sizeof(inputs)/sizeof((inputs)[0]); i++) { \
		long double result; CLEAR(); result = (operation)((inputs)[i]); \
		if (emit_long_double((id), (uint16_t)i, mode, 0, result) != 0) return -1; \
	} \
} while (0)
#define RUN_D_INTEGER(id, operation, inputs) do { \
	size_t i; for (i = 0; i < sizeof(inputs)/sizeof((inputs)[0]); i++) { \
		long long result; CLEAR(); result = (operation)((inputs)[i]); \
		if (emit_integer((id), (uint16_t)i, mode, result) != 0) return -1; \
	} \
} while (0)
#define RUN_F_INTEGER(id, operation, inputs) do { \
	size_t i; for (i = 0; i < sizeof(inputs)/sizeof((inputs)[0]); i++) { \
		long long result; CLEAR(); result = (operation)((inputs)[i]); \
		if (emit_integer((id), (uint16_t)i, mode, result) != 0) return -1; \
	} \
} while (0)
#define RUN_L_INTEGER(id, operation, inputs) do { \
	size_t i; for (i = 0; i < sizeof(inputs)/sizeof((inputs)[0]); i++) { \
		long long result; CLEAR(); result = (operation)((inputs)[i]); \
		if (emit_integer((id), (uint16_t)i, mode, result) != 0) return -1; \
	} \
} while (0)

static int run_binary(int mode)
{
	size_t i;
	for (i = 0; i < sizeof(d_pairs)/sizeof(d_pairs[0]); i++) {
		double result; int quotient;
#define D_BINARY(id, operation) do { CLEAR(); result = (operation)(d_pairs[i].left, d_pairs[i].right); if (emit_double((id), (uint16_t)i, mode, 0, result) != 0) return -1; } while (0)
		D_BINARY(ID_DREM, direct_drem);
		D_BINARY(ID_REMAINDER, direct_remainder);
		CLEAR(); quotient = 0x5a5a5a5a; result = direct_remquo(d_pairs[i].left, d_pairs[i].right, &quotient);
		if (emit_double(ID_REMQUO, (uint16_t)i, mode, quotient, result) != 0) return -1;
#undef D_BINARY
	}
	for (i = 0; i < sizeof(f_pairs)/sizeof(f_pairs[0]); i++) {
		float result; int quotient;
#define F_BINARY(id, operation) do { CLEAR(); result = (operation)(f_pairs[i].left, f_pairs[i].right); if (emit_float((id), (uint16_t)i, mode, 0, result) != 0) return -1; } while (0)
		F_BINARY(ID_DREMF, direct_dremf);
		F_BINARY(ID_REMAINDERF, direct_remainderf);
		CLEAR(); quotient = 0x5a5a5a5a; result = direct_remquof(f_pairs[i].left, f_pairs[i].right, &quotient);
		if (emit_float(ID_REMQUOF, (uint16_t)i, mode, quotient, result) != 0) return -1;
#undef F_BINARY
	}
	for (i = 0; i < sizeof(l_pairs)/sizeof(l_pairs[0]); i++) {
		long double result; int quotient;
		CLEAR(); result = direct_remainderl(l_pairs[i].left, l_pairs[i].right);
		if (emit_long_double(ID_REMAINDERL, (uint16_t)i, mode, 0, result) != 0) return -1;
		CLEAR(); quotient = 0x5a5a5a5a; result = direct_remquol(l_pairs[i].left, l_pairs[i].right, &quotient);
		if (emit_long_double(ID_REMQUOL, (uint16_t)i, mode, quotient, result) != 0) return -1;
	}
	return 0;
}

static int run_decomposition(int mode)
{
	size_t i;
	for (i = 0; i < sizeof(d_values)/sizeof(d_values[0]); i++) {
		double result, integer; int exponent;
		CLEAR(); exponent = 0x5a5a5a5a; result = direct_frexp(d_values[i], &exponent);
		if (emit_double(ID_FREXP, (uint16_t)i, mode, exponent, result) != 0) return -1;
		CLEAR(); integer = 123.0; result = direct_modf(d_values[i], &integer);
		if (emit_double(ID_MODF, (uint16_t)i, mode, 0, result) != 0 ||
			emit_double(ID_MODF, (uint16_t)(0x8000U | i), mode, 0, integer) != 0) return -1;
	}
	for (i = 0; i < sizeof(f_values)/sizeof(f_values[0]); i++) {
		float result, integer; int exponent;
		CLEAR(); exponent = 0x5a5a5a5a; result = direct_frexpf(f_values[i], &exponent);
		if (emit_float(ID_FREXPF, (uint16_t)i, mode, exponent, result) != 0) return -1;
		CLEAR(); integer = 123.0f; result = direct_modff(f_values[i], &integer);
		if (emit_float(ID_MODFF, (uint16_t)i, mode, 0, result) != 0 ||
			emit_float(ID_MODFF, (uint16_t)(0x8000U | i), mode, 0, integer) != 0) return -1;
	}
	for (i = 0; i < sizeof(l_values)/sizeof(l_values[0]); i++) {
		long double result, integer; int exponent;
		CLEAR(); exponent = 0x5a5a5a5a; result = direct_frexpl(l_values[i], &exponent);
		if (emit_long_double(ID_FREXPL, (uint16_t)i, mode, exponent, result) != 0) return -1;
		CLEAR(); integer = 123.0L; result = direct_modfl(l_values[i], &integer);
		if (emit_long_double(ID_MODFL, (uint16_t)i, mode, 0, result) != 0 ||
			emit_long_double(ID_MODFL, (uint16_t)(0x8000U | i), mode, 0, integer) != 0) return -1;
	}
	return 0;
}

static int run_scaling(int mode)
{
	size_t i;
	for (i = 0; i < sizeof(d_scales)/sizeof(d_scales[0]); i++) {
		double result;
		CLEAR(); result = direct_ldexp(d_scales[i].value, d_scales[i].exponent);
		if (emit_double(ID_LDEXP, (uint16_t)i, mode, 0, result) != 0) return -1;
		CLEAR(); result = direct_scalbn(d_scales[i].value, d_scales[i].exponent);
		if (emit_double(ID_SCALBN, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(f_scales)/sizeof(f_scales[0]); i++) {
		float result;
		CLEAR(); result = direct_ldexpf(f_scales[i].value, f_scales[i].exponent);
		if (emit_float(ID_LDEXPF, (uint16_t)i, mode, 0, result) != 0) return -1;
		CLEAR(); result = direct_scalbnf(f_scales[i].value, f_scales[i].exponent);
		if (emit_float(ID_SCALBNF, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(l_scales)/sizeof(l_scales[0]); i++) {
		long double result;
		CLEAR(); result = direct_ldexpl(l_scales[i].value, l_scales[i].exponent);
		if (emit_long_double(ID_LDEXPL, (uint16_t)i, mode, 0, result) != 0) return -1;
		CLEAR(); result = direct_scalbnl(l_scales[i].value, l_scales[i].exponent);
		if (emit_long_double(ID_SCALBNL, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(d_long_scales)/sizeof(d_long_scales[0]); i++) {
		double result; CLEAR(); result = direct_scalbln(d_long_scales[i].value, d_long_scales[i].exponent);
		if (emit_double(ID_SCALBLN, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(f_long_scales)/sizeof(f_long_scales[0]); i++) {
		float result; CLEAR(); result = direct_scalblnf(f_long_scales[i].value, f_long_scales[i].exponent);
		if (emit_float(ID_SCALBLNF, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(l_long_scales)/sizeof(l_long_scales[0]); i++) {
		long double result; CLEAR(); result = direct_scalblnl(l_long_scales[i].value, l_long_scales[i].exponent);
		if (emit_long_double(ID_SCALBLNL, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(d_scalb_pairs)/sizeof(d_scalb_pairs[0]); i++) {
		double result; CLEAR(); result = direct_scalb(d_scalb_pairs[i].left, d_scalb_pairs[i].right);
		if (emit_double(ID_SCALB, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(f_scalb_pairs)/sizeof(f_scalb_pairs[0]); i++) {
		float result; CLEAR(); result = direct_scalbf(f_scalb_pairs[i].left, f_scalb_pairs[i].right);
		if (emit_float(ID_SCALBF, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	return 0;
}

static int run_next(int mode)
{
	size_t i;
	for (i = 0; i < sizeof(d_next)/sizeof(d_next[0]); i++) {
		double result; CLEAR(); result = direct_nextafter(d_next[i].left, d_next[i].right);
		if (emit_double(ID_NEXTAFTER, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(f_next)/sizeof(f_next[0]); i++) {
		float result; CLEAR(); result = direct_nextafterf(f_next[i].left, f_next[i].right);
		if (emit_float(ID_NEXTAFTERF, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(l_next)/sizeof(l_next[0]); i++) {
		long double result;
		CLEAR(); result = direct_nextafterl(l_next[i].left, l_next[i].right);
		if (emit_long_double(ID_NEXTAFTERL, (uint16_t)i, mode, 0, result) != 0) return -1;
		CLEAR(); result = direct_nexttowardl(l_next[i].left, l_next[i].right);
		if (emit_long_double(ID_NEXTTOWARDL, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(d_toward)/sizeof(d_toward[0]); i++) {
		double result; CLEAR(); result = direct_nexttoward(d_toward[i].value, d_toward[i].toward);
		if (emit_double(ID_NEXTTOWARD, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(f_toward)/sizeof(f_toward[0]); i++) {
		float result; CLEAR(); result = direct_nexttowardf(f_toward[i].value, f_toward[i].toward);
		if (emit_float(ID_NEXTTOWARDF, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	return 0;
}

static int run_gamma(int mode)
{
	size_t i;
	for (i = 0; i < sizeof(d_special)/sizeof(d_special[0]); i++) {
		double result; int sign;
		CLEAR(); signgam = __signgam = 0x5a5a5a5a; result = direct_lgamma(d_special[i]);
		if (emit_double(ID_LGAMMA, (uint16_t)i, mode, signgam, result) != 0 || signgam != __signgam) return -1;
		CLEAR(); sign = 0x5a5a5a5a; result = direct_lgamma_r(d_special[i], &sign);
		if (emit_double(ID_LGAMMA_R, (uint16_t)i, mode, sign, result) != 0) return -1;
		CLEAR(); result = direct_tgamma(d_special[i]);
		if (emit_double(ID_TGAMMA, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(f_special)/sizeof(f_special[0]); i++) {
		float result; int sign;
		CLEAR(); signgam = __signgam = 0x5a5a5a5a; result = direct_lgammaf(f_special[i]);
		if (emit_float(ID_LGAMMAF, (uint16_t)i, mode, signgam, result) != 0 || signgam != __signgam) return -1;
		CLEAR(); sign = 0x5a5a5a5a; result = direct_lgammaf_r(f_special[i], &sign);
		if (emit_float(ID_LGAMMAF_R, (uint16_t)i, mode, sign, result) != 0) return -1;
		CLEAR(); result = direct_tgammaf(f_special[i]);
		if (emit_float(ID_TGAMMAF, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(l_special)/sizeof(l_special[0]); i++) {
		long double result; int sign;
		CLEAR(); sign = 0x5a5a5a5a; result = direct___lgammal_r(l_special[i], &sign);
		if (emit_long_double(ID_LGAMMAL_INTERNAL_R, (uint16_t)i, mode, sign, result) != 0) return -1;
		CLEAR(); signgam = __signgam = 0x5a5a5a5a; result = direct_lgammal(l_special[i]);
		if (emit_long_double(ID_LGAMMAL, (uint16_t)i, mode, signgam, result) != 0 || signgam != __signgam) return -1;
		CLEAR(); sign = 0x5a5a5a5a; result = direct_lgammal_r(l_special[i], &sign);
		if (emit_long_double(ID_LGAMMAL_R, (uint16_t)i, mode, sign, result) != 0) return -1;
		CLEAR(); result = direct_tgammal(l_special[i]);
		if (emit_long_double(ID_TGAMMAL, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	return 0;
}

static int run_bessel(int mode)
{
	size_t i;
	RUN_D_UNARY(ID_J0, direct_j0, d_bessel);
	RUN_F_UNARY(ID_J0F, direct_j0f, f_bessel);
	RUN_D_UNARY(ID_J1, direct_j1, d_bessel);
	RUN_F_UNARY(ID_J1F, direct_j1f, f_bessel);
	RUN_D_UNARY(ID_Y0, direct_y0, d_bessel);
	RUN_F_UNARY(ID_Y0F, direct_y0f, f_bessel);
	RUN_D_UNARY(ID_Y1, direct_y1, d_bessel);
	RUN_F_UNARY(ID_Y1F, direct_y1f, f_bessel);
	for (i = 0; i < sizeof(d_orders)/sizeof(d_orders[0]); i++) {
		double result;
		CLEAR(); result = direct_jn(d_orders[i].order, d_orders[i].value);
		if (emit_double(ID_JN, (uint16_t)i, mode, 0, result) != 0) return -1;
		CLEAR(); result = direct_yn(d_orders[i].order, d_orders[i].value);
		if (emit_double(ID_YN, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	for (i = 0; i < sizeof(f_orders)/sizeof(f_orders[0]); i++) {
		float result;
		CLEAR(); result = direct_jnf(f_orders[i].order, f_orders[i].value);
		if (emit_float(ID_JNF, (uint16_t)i, mode, 0, result) != 0) return -1;
		CLEAR(); result = direct_ynf(f_orders[i].order, f_orders[i].value);
		if (emit_float(ID_YNF, (uint16_t)i, mode, 0, result) != 0) return -1;
	}
	return 0;
}

static int run_mode(int mode)
{
	size_t i;
	RUN_D_INTEGER(ID_FPCLASSIFY, direct___fpclassify, d_values);
	RUN_F_INTEGER(ID_FPCLASSIFYF, direct___fpclassifyf, f_values);
	RUN_L_INTEGER(ID_FPCLASSIFYL, direct___fpclassifyl, l_values);
	RUN_D_INTEGER(ID_SIGNBIT, direct___signbit, d_values);
	RUN_F_INTEGER(ID_SIGNBITF, direct___signbitf, f_values);
	RUN_L_INTEGER(ID_SIGNBITL, direct___signbitl, l_values);
	RUN_D_INTEGER(ID_FINITE, direct_finite, d_values);
	RUN_F_INTEGER(ID_FINITEF, direct_finitef, f_values);
	RUN_D_INTEGER(ID_ILOGB, direct_ilogb, d_values);
	RUN_F_INTEGER(ID_ILOGBF, direct_ilogbf, f_values);
	RUN_L_INTEGER(ID_ILOGBL, direct_ilogbl, l_values);
	RUN_D_INTEGER(ID_LLRINT, direct_llrint, d_values);
	RUN_F_INTEGER(ID_LLRINTF, direct_llrintf, f_values);
	RUN_L_INTEGER(ID_LLRINTL, direct_llrintl, l_values);
	RUN_D_INTEGER(ID_LLROUND, direct_llround, d_values);
	RUN_F_INTEGER(ID_LLROUNDF, direct_llroundf, f_values);
	RUN_L_INTEGER(ID_LLROUNDL, direct_llroundl, l_values);
	RUN_D_INTEGER(ID_LRINT, direct_lrint, d_values);
	RUN_F_INTEGER(ID_LRINTF, direct_lrintf, f_values);
	RUN_L_INTEGER(ID_LRINTL, direct_lrintl, l_values);
	RUN_D_INTEGER(ID_LROUND, direct_lround, d_values);
	RUN_F_INTEGER(ID_LROUNDF, direct_lroundf, f_values);
	RUN_L_INTEGER(ID_LROUNDL, direct_lroundl, l_values);
	RUN_D_UNARY(ID_ERF, direct_erf, d_special);
	RUN_D_UNARY(ID_ERFC, direct_erfc, d_special);
	RUN_F_UNARY(ID_ERFCF, direct_erfcf, f_special);
	RUN_L_UNARY(ID_ERFCL, direct_erfcl, l_special);
	RUN_F_UNARY(ID_ERFF, direct_erff, f_special);
	RUN_L_UNARY(ID_ERFL, direct_erfl, l_special);
	RUN_D_UNARY(ID_LOGB, direct_logb, d_values);
	RUN_F_UNARY(ID_LOGBF, direct_logbf, f_values);
	RUN_L_UNARY(ID_LOGBL, direct_logbl, l_values);
	RUN_D_UNARY(ID_SIGNIFICAND, direct_significand, d_values);
	RUN_F_UNARY(ID_SIGNIFICANDF, direct_significandf, f_values);
	for (i = 0; i < sizeof(nan_tags)/sizeof(nan_tags[0]); i++) {
		double d; float f; long double l;
		CLEAR(); d = direct_nan(nan_tags[i]); if (emit_double(ID_NAN, (uint16_t)i, mode, 0, d) != 0) return -1;
		CLEAR(); f = direct_nanf(nan_tags[i]); if (emit_float(ID_NANF, (uint16_t)i, mode, 0, f) != 0) return -1;
		CLEAR(); l = direct_nanl(nan_tags[i]); if (emit_long_double(ID_NANL, (uint16_t)i, mode, 0, l) != 0) return -1;
	}
	if (run_binary(mode) != 0 || run_decomposition(mode) != 0 ||
		run_scaling(mode) != 0 || run_next(mode) != 0 ||
		run_gamma(mode) != 0 || run_bessel(mode) != 0) return -1;
	return 0;
}

int crabc_x86_64_math_special_probe(void)
{
	size_t mode;
	if (&signgam != &__signgam) return 91;
	for (mode = 0; mode < sizeof(rounding_modes)/sizeof(rounding_modes[0]); mode++) {
		if (fesetround(rounding_modes[mode]) != 0) return 92;
		if (run_mode(rounding_modes[mode]) != 0) return 93;
	}
	if (fesetround(FE_TONEAREST) != 0 || feclearexcept(FE_ALL_EXCEPT) != 0)
		return 94;
	return 0;
}

#ifndef CRABC_MATH_SPECIAL_FREESTANDING
int main(void) { return crabc_x86_64_math_special_probe(); }
#endif
