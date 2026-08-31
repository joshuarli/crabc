/* Exact native Linux/x86-64 differential for the complete math.complex capability. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <complex.h>
#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>

#pragma STDC FENV_ACCESS ON

_Static_assert(sizeof(float complex) == 8 && _Alignof(float complex) == 4,
	"x86 float complex storage");
_Static_assert(sizeof(double complex) == 16 && _Alignof(double complex) == 8,
	"x86 double complex storage");
_Static_assert(sizeof(long double) == 16 && _Alignof(long double) == 16 &&
	LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384,
	"x86 binary80 storage");
_Static_assert(sizeof(long double complex) == 32 &&
	_Alignof(long double complex) == 16,
	"x86 binary80 complex storage");

typedef double (*d_real)(double complex);
typedef float (*f_real)(float complex);
typedef long double (*l_real)(long double complex);
typedef double complex (*d_unary)(double complex);
typedef float complex (*f_unary)(float complex);
typedef long double complex (*l_unary)(long double complex);
typedef double complex (*d_binary)(double complex, double complex);
typedef float complex (*f_binary)(float complex, float complex);
typedef long double complex (*l_binary)(long double complex, long double complex);

#define DIRECT(type, name) static type direct_##name = (name)
DIRECT(d_real, cabs); DIRECT(f_real, cabsf); DIRECT(l_real, cabsl);
DIRECT(d_unary, cacos); DIRECT(f_unary, cacosf); DIRECT(d_unary, cacosh);
DIRECT(f_unary, cacoshf); DIRECT(l_unary, cacoshl); DIRECT(l_unary, cacosl);
DIRECT(d_real, carg); DIRECT(f_real, cargf); DIRECT(l_real, cargl);
DIRECT(d_unary, casin); DIRECT(f_unary, casinf); DIRECT(d_unary, casinh);
DIRECT(f_unary, casinhf); DIRECT(l_unary, casinhl); DIRECT(l_unary, casinl);
DIRECT(d_unary, catan); DIRECT(f_unary, catanf); DIRECT(d_unary, catanh);
DIRECT(f_unary, catanhf); DIRECT(l_unary, catanhl); DIRECT(l_unary, catanl);
DIRECT(d_unary, ccos); DIRECT(f_unary, ccosf); DIRECT(d_unary, ccosh);
DIRECT(f_unary, ccoshf); DIRECT(l_unary, ccoshl); DIRECT(l_unary, ccosl);
DIRECT(d_unary, cexp); DIRECT(f_unary, cexpf); DIRECT(l_unary, cexpl);
DIRECT(d_real, cimag); DIRECT(f_real, cimagf); DIRECT(l_real, cimagl);
DIRECT(d_unary, clog); DIRECT(f_unary, clogf); DIRECT(l_unary, clogl);
DIRECT(d_unary, conj); DIRECT(f_unary, conjf); DIRECT(l_unary, conjl);
DIRECT(d_binary, cpow); DIRECT(f_binary, cpowf); DIRECT(l_binary, cpowl);
DIRECT(d_unary, cproj); DIRECT(f_unary, cprojf); DIRECT(l_unary, cprojl);
DIRECT(d_real, creal); DIRECT(f_real, crealf); DIRECT(l_real, creall);
DIRECT(d_unary, csin); DIRECT(f_unary, csinf); DIRECT(d_unary, csinh);
DIRECT(f_unary, csinhf); DIRECT(l_unary, csinhl); DIRECT(l_unary, csinl);
DIRECT(d_unary, csqrt); DIRECT(f_unary, csqrtf); DIRECT(l_unary, csqrtl);
DIRECT(d_unary, ctan); DIRECT(f_unary, ctanf); DIRECT(d_unary, ctanh);
DIRECT(f_unary, ctanhf); DIRECT(l_unary, ctanhl); DIRECT(l_unary, ctanl);
#undef DIRECT

enum function_id {
	ID_CABS = 1, ID_CABSF, ID_CABSL, ID_CACOS, ID_CACOSF, ID_CACOSH,
	ID_CACOSHF, ID_CACOSHL, ID_CACOSL, ID_CARG, ID_CARGF, ID_CARGL,
	ID_CASIN, ID_CASINF, ID_CASINH, ID_CASINHF, ID_CASINHL, ID_CASINL,
	ID_CATAN, ID_CATANF, ID_CATANH, ID_CATANHF, ID_CATANHL, ID_CATANL,
	ID_CCOS, ID_CCOSF, ID_CCOSH, ID_CCOSHF, ID_CCOSHL, ID_CCOSL,
	ID_CEXP, ID_CEXPF, ID_CEXPL, ID_CIMAG, ID_CIMAGF, ID_CIMAGL,
	ID_CLOG, ID_CLOGF, ID_CLOGL, ID_CONJ, ID_CONJF, ID_CONJL,
	ID_CPOW, ID_CPOWF, ID_CPOWL, ID_CPROJ, ID_CPROJF, ID_CPROJL,
	ID_CREAL, ID_CREALF, ID_CREALL, ID_CSIN, ID_CSINF, ID_CSINH,
	ID_CSINHF, ID_CSINHL, ID_CSINL, ID_CSQRT, ID_CSQRTF, ID_CSQRTL,
	ID_CTAN, ID_CTANF, ID_CTANH, ID_CTANHF, ID_CTANHL, ID_CTANL,
};

struct __attribute__((packed)) result_record {
	uint16_t function;
	uint16_t case_index;
	uint32_t rounding;
	uint32_t exceptions;
	uint32_t kind;
	unsigned char value[48];
};
_Static_assert(sizeof(struct result_record) == 64, "stable complex result record");

struct f_pair { float complex left; float complex right; };
struct d_pair { double complex left; double complex right; };
struct l_pair { long double complex left; long double complex right; };

static const int rounding_modes[] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};

static const float complex f_values[] = {
	CMPLXF(0.0f, 0.0f), CMPLXF(-0.0f, 0.0f), CMPLXF(0.0f, -0.0f),
	CMPLXF(1.0f, 0.0f), CMPLXF(-1.0f, 0.0f), CMPLXF(0.0f, 1.0f),
	CMPLXF(0.0f, -1.0f), CMPLXF(1.0f, 1.0f), CMPLXF(-1.0f, 1.0f),
	CMPLXF(0x1p-1f, -0x1.8p-1f), CMPLXF(FLT_MIN, FLT_TRUE_MIN),
	CMPLXF(FLT_MAX / 4.0f, FLT_MAX / 8.0f),
	CMPLXF(__builtin_inff(), 0.0f), CMPLXF(-__builtin_inff(), 0.0f),
	CMPLXF(0.0f, __builtin_inff()), CMPLXF(1.0f, __builtin_inff()),
	CMPLXF(__builtin_inff(), 1.0f),
	CMPLXF(__builtin_inff(), __builtin_inff()),
	CMPLXF(__builtin_nanf("0x123"), 0.0f),
	CMPLXF(0.0f, __builtin_nanf("0x234")),
	CMPLXF(__builtin_nanf("0x345"), 1.0f),
	CMPLXF(1.0f, __builtin_nanf("0x456")),
};
static const double complex d_values[] = {
	CMPLX(0.0, 0.0), CMPLX(-0.0, 0.0), CMPLX(0.0, -0.0),
	CMPLX(1.0, 0.0), CMPLX(-1.0, 0.0), CMPLX(0.0, 1.0),
	CMPLX(0.0, -1.0), CMPLX(1.0, 1.0), CMPLX(-1.0, 1.0),
	CMPLX(0x1p-1, -0x1.8p-1), CMPLX(DBL_MIN, DBL_TRUE_MIN),
	CMPLX(DBL_MAX / 4.0, DBL_MAX / 8.0),
	CMPLX(__builtin_inf(), 0.0), CMPLX(-__builtin_inf(), 0.0),
	CMPLX(0.0, __builtin_inf()), CMPLX(1.0, __builtin_inf()),
	CMPLX(__builtin_inf(), 1.0), CMPLX(__builtin_inf(), __builtin_inf()),
	CMPLX(__builtin_nan("0x1234"), 0.0),
	CMPLX(0.0, __builtin_nan("0x2345")),
	CMPLX(__builtin_nan("0x3456"), 1.0),
	CMPLX(1.0, __builtin_nan("0x4567")),
};
static const long double complex l_values[] = {
	CMPLXL(0.0L, 0.0L), CMPLXL(-0.0L, 0.0L), CMPLXL(0.0L, -0.0L),
	CMPLXL(1.0L, 0.0L), CMPLXL(-1.0L, 0.0L), CMPLXL(0.0L, 1.0L),
	CMPLXL(0.0L, -1.0L), CMPLXL(1.0L, 1.0L), CMPLXL(-1.0L, 1.0L),
	CMPLXL(0x1p-1L, -0x1.8p-1L), CMPLXL(LDBL_MIN, LDBL_TRUE_MIN),
	CMPLXL(LDBL_MAX / 4.0L, LDBL_MAX / 8.0L),
	CMPLXL(__builtin_infl(), 0.0L), CMPLXL(-__builtin_infl(), 0.0L),
	CMPLXL(0.0L, __builtin_infl()), CMPLXL(1.0L, __builtin_infl()),
	CMPLXL(__builtin_infl(), 1.0L), CMPLXL(__builtin_infl(), __builtin_infl()),
	CMPLXL(__builtin_nanl("0x1234"), 0.0L),
	CMPLXL(0.0L, __builtin_nanl("0x2345")),
	CMPLXL(__builtin_nanl("0x3456"), 1.0L),
	CMPLXL(1.0L, __builtin_nanl("0x4567")),
};

static const struct f_pair f_pairs[] = {
	{CMPLXF(1.0f, 1.0f), CMPLXF(2.0f, -1.0f)},
	{CMPLXF(-1.0f, 1.0f), CMPLXF(0x1p-1f, 0x1p-2f)},
	{CMPLXF(0.0f, 0.0f), CMPLXF(0.0f, 0.0f)},
	{CMPLXF(-0.0f, 0.0f), CMPLXF(1.0f, 0.0f)},
	{CMPLXF(1.0f, 0.0f), CMPLXF(0.0f, 0.0f)},
	{CMPLXF(0.0f, 1.0f), CMPLXF(2.0f, 0.0f)},
	{CMPLXF(FLT_MIN, FLT_TRUE_MIN), CMPLXF(-1.0f, 1.0f)},
	{CMPLXF(FLT_MAX / 4.0f, 1.0f), CMPLXF(2.0f, 0.0f)},
	{CMPLXF(__builtin_inff(), 0.0f), CMPLXF(0.0f, 1.0f)},
	{CMPLXF(1.0f, __builtin_inff()), CMPLXF(1.0f, 1.0f)},
	{CMPLXF(__builtin_nanf("0x12"), 0.0f), CMPLXF(1.0f, 1.0f)},
	{CMPLXF(1.0f, 1.0f), CMPLXF(__builtin_nanf("0x23"), 0.0f)},
	{CMPLXF(__builtin_inff(), __builtin_inff()), CMPLXF(0.0f, 0.0f)},
	{CMPLXF(-1.0f, -0.0f), CMPLXF(0x1p-1f, __builtin_inff())},
};
static const struct d_pair d_pairs[] = {
	{CMPLX(1.0, 1.0), CMPLX(2.0, -1.0)},
	{CMPLX(-1.0, 1.0), CMPLX(0x1p-1, 0x1p-2)},
	{CMPLX(0.0, 0.0), CMPLX(0.0, 0.0)},
	{CMPLX(-0.0, 0.0), CMPLX(1.0, 0.0)},
	{CMPLX(1.0, 0.0), CMPLX(0.0, 0.0)},
	{CMPLX(0.0, 1.0), CMPLX(2.0, 0.0)},
	{CMPLX(DBL_MIN, DBL_TRUE_MIN), CMPLX(-1.0, 1.0)},
	{CMPLX(DBL_MAX / 4.0, 1.0), CMPLX(2.0, 0.0)},
	{CMPLX(__builtin_inf(), 0.0), CMPLX(0.0, 1.0)},
	{CMPLX(1.0, __builtin_inf()), CMPLX(1.0, 1.0)},
	{CMPLX(__builtin_nan("0x12"), 0.0), CMPLX(1.0, 1.0)},
	{CMPLX(1.0, 1.0), CMPLX(__builtin_nan("0x23"), 0.0)},
	{CMPLX(__builtin_inf(), __builtin_inf()), CMPLX(0.0, 0.0)},
	{CMPLX(-1.0, -0.0), CMPLX(0x1p-1, __builtin_inf())},
};
static const struct l_pair l_pairs[] = {
	{CMPLXL(1.0L, 1.0L), CMPLXL(2.0L, -1.0L)},
	{CMPLXL(-1.0L, 1.0L), CMPLXL(0x1p-1L, 0x1p-2L)},
	{CMPLXL(0.0L, 0.0L), CMPLXL(0.0L, 0.0L)},
	{CMPLXL(-0.0L, 0.0L), CMPLXL(1.0L, 0.0L)},
	{CMPLXL(1.0L, 0.0L), CMPLXL(0.0L, 0.0L)},
	{CMPLXL(0.0L, 1.0L), CMPLXL(2.0L, 0.0L)},
	{CMPLXL(LDBL_MIN, LDBL_TRUE_MIN), CMPLXL(-1.0L, 1.0L)},
	{CMPLXL(LDBL_MAX / 4.0L, 1.0L), CMPLXL(2.0L, 0.0L)},
	{CMPLXL(__builtin_infl(), 0.0L), CMPLXL(0.0L, 1.0L)},
	{CMPLXL(1.0L, __builtin_infl()), CMPLXL(1.0L, 1.0L)},
	{CMPLXL(__builtin_nanl("0x12"), 0.0L), CMPLXL(1.0L, 1.0L)},
	{CMPLXL(1.0L, 1.0L), CMPLXL(__builtin_nanl("0x23"), 0.0L)},
	{CMPLXL(__builtin_infl(), __builtin_infl()), CMPLXL(0.0L, 0.0L)},
	{CMPLXL(-1.0L, -0.0L), CMPLXL(0x1p-1L, __builtin_infl())},
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

static void clear_value(unsigned char *value)
{
	size_t index;
	for (index = 0; index < 48; index++) value[index] = 0;
}

static void copy_bytes(unsigned char *destination, const unsigned char *source,
	size_t count)
{
	size_t index;
	for (index = 0; index < count; index++) destination[index] = source[index];
}

static int emit_record(uint16_t function, uint16_t case_index, int rounding,
	uint32_t kind, const unsigned char *value)
{
	struct result_record record;
	record.function = function;
	record.case_index = case_index;
	record.rounding = (uint32_t)rounding;
	record.exceptions = (uint32_t)fetestexcept(FE_ALL_EXCEPT);
	record.kind = kind;
	copy_bytes(record.value, value, 48);
	return raw_write(&record, sizeof(record)) == 0 ? 0 : -1;
}

static int emit_float_real(uint16_t id, uint16_t index, int mode, float value)
{
	union { float value; unsigned char bytes[4]; } bits = { value };
	unsigned char payload[48]; clear_value(payload); copy_bytes(payload, bits.bytes, 4);
	return emit_record(id, index, mode, 1, payload);
}

static int emit_double_real(uint16_t id, uint16_t index, int mode, double value)
{
	union { double value; unsigned char bytes[8]; } bits = { value };
	unsigned char payload[48]; clear_value(payload); copy_bytes(payload, bits.bytes, 8);
	return emit_record(id, index, mode, 2, payload);
}

static int emit_long_real(uint16_t id, uint16_t index, int mode, long double value)
{
	union { long double value; unsigned char bytes[16]; } bits = { value };
	unsigned char payload[48]; clear_value(payload); copy_bytes(payload, bits.bytes, 10);
	return emit_record(id, index, mode, 3, payload);
}

static int emit_float_complex(uint16_t id, uint16_t index, int mode,
	float complex value)
{
	union { float value; unsigned char bytes[4]; } re = { __real__ value };
	union { float value; unsigned char bytes[4]; } im = { __imag__ value };
	unsigned char payload[48]; clear_value(payload);
	copy_bytes(payload, re.bytes, 4); copy_bytes(payload + 4, im.bytes, 4);
	return emit_record(id, index, mode, 4, payload);
}

static int emit_double_complex(uint16_t id, uint16_t index, int mode,
	double complex value)
{
	union { double value; unsigned char bytes[8]; } re = { __real__ value };
	union { double value; unsigned char bytes[8]; } im = { __imag__ value };
	unsigned char payload[48]; clear_value(payload);
	copy_bytes(payload, re.bytes, 8); copy_bytes(payload + 8, im.bytes, 8);
	return emit_record(id, index, mode, 5, payload);
}

static int emit_long_complex(uint16_t id, uint16_t index, int mode,
	long double complex value)
{
	union { long double value; unsigned char bytes[16]; } re = { __real__ value };
	union { long double value; unsigned char bytes[16]; } im = { __imag__ value };
	unsigned char payload[48]; clear_value(payload);
	copy_bytes(payload, re.bytes, 10); copy_bytes(payload + 16, im.bytes, 10);
	return emit_record(id, index, mode, 6, payload);
}

#define CLEAR() do { if (feclearexcept(FE_ALL_EXCEPT) != 0) return -1; } while (0)
#define RUN_REAL(id, operation, inputs, type, emitter) do { \
	size_t i; for (i = 0; i < sizeof(inputs) / sizeof((inputs)[0]); i++) { \
		type result; CLEAR(); result = (operation)((inputs)[i]); \
		if ((emitter)((id), (uint16_t)i, mode, result) != 0) return -1; \
	} \
} while (0)
#define RUN_UNARY(id, operation, inputs, type, emitter) do { \
	size_t i; for (i = 0; i < sizeof(inputs) / sizeof((inputs)[0]); i++) { \
		type result; CLEAR(); result = (operation)((inputs)[i]); \
		if ((emitter)((id), (uint16_t)i, mode, result) != 0) return -1; \
	} \
} while (0)
#define RUN_BINARY(id, operation, inputs, type, emitter) do { \
	size_t i; for (i = 0; i < sizeof(inputs) / sizeof((inputs)[0]); i++) { \
		type result; CLEAR(); result = (operation)((inputs)[i].left, (inputs)[i].right); \
		if ((emitter)((id), (uint16_t)i, mode, result) != 0) return -1; \
	} \
} while (0)

static int run_float(int mode)
{
	RUN_REAL(ID_CABSF, direct_cabsf, f_values, float, emit_float_real);
	RUN_REAL(ID_CARGF, direct_cargf, f_values, float, emit_float_real);
	RUN_REAL(ID_CIMAGF, direct_cimagf, f_values, float, emit_float_real);
	RUN_REAL(ID_CREALF, direct_crealf, f_values, float, emit_float_real);
	RUN_UNARY(ID_CACOSF, direct_cacosf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CACOSHF, direct_cacoshf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CASINF, direct_casinf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CASINHF, direct_casinhf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CATANF, direct_catanf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CATANHF, direct_catanhf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CCOSF, direct_ccosf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CCOSHF, direct_ccoshf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CEXPF, direct_cexpf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CLOGF, direct_clogf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CONJF, direct_conjf, f_values, float complex, emit_float_complex);
	RUN_BINARY(ID_CPOWF, direct_cpowf, f_pairs, float complex, emit_float_complex);
	RUN_UNARY(ID_CPROJF, direct_cprojf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CSINF, direct_csinf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CSINHF, direct_csinhf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CSQRTF, direct_csqrtf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CTANF, direct_ctanf, f_values, float complex, emit_float_complex);
	RUN_UNARY(ID_CTANHF, direct_ctanhf, f_values, float complex, emit_float_complex);
	return 0;
}

static int run_double(int mode)
{
	RUN_REAL(ID_CABS, direct_cabs, d_values, double, emit_double_real);
	RUN_REAL(ID_CARG, direct_carg, d_values, double, emit_double_real);
	RUN_REAL(ID_CIMAG, direct_cimag, d_values, double, emit_double_real);
	RUN_REAL(ID_CREAL, direct_creal, d_values, double, emit_double_real);
	RUN_UNARY(ID_CACOS, direct_cacos, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CACOSH, direct_cacosh, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CASIN, direct_casin, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CASINH, direct_casinh, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CATAN, direct_catan, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CATANH, direct_catanh, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CCOS, direct_ccos, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CCOSH, direct_ccosh, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CEXP, direct_cexp, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CLOG, direct_clog, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CONJ, direct_conj, d_values, double complex, emit_double_complex);
	RUN_BINARY(ID_CPOW, direct_cpow, d_pairs, double complex, emit_double_complex);
	RUN_UNARY(ID_CPROJ, direct_cproj, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CSIN, direct_csin, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CSINH, direct_csinh, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CSQRT, direct_csqrt, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CTAN, direct_ctan, d_values, double complex, emit_double_complex);
	RUN_UNARY(ID_CTANH, direct_ctanh, d_values, double complex, emit_double_complex);
	return 0;
}

static int run_long_double(int mode)
{
	RUN_REAL(ID_CABSL, direct_cabsl, l_values, long double, emit_long_real);
	RUN_REAL(ID_CARGL, direct_cargl, l_values, long double, emit_long_real);
	RUN_REAL(ID_CIMAGL, direct_cimagl, l_values, long double, emit_long_real);
	RUN_REAL(ID_CREALL, direct_creall, l_values, long double, emit_long_real);
	RUN_UNARY(ID_CACOSL, direct_cacosl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CACOSHL, direct_cacoshl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CASINL, direct_casinl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CASINHL, direct_casinhl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CATANL, direct_catanl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CATANHL, direct_catanhl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CCOSL, direct_ccosl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CCOSHL, direct_ccoshl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CEXPL, direct_cexpl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CLOGL, direct_clogl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CONJL, direct_conjl, l_values, long double complex, emit_long_complex);
	RUN_BINARY(ID_CPOWL, direct_cpowl, l_pairs, long double complex, emit_long_complex);
	RUN_UNARY(ID_CPROJL, direct_cprojl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CSINL, direct_csinl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CSINHL, direct_csinhl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CSQRTL, direct_csqrtl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CTANL, direct_ctanl, l_values, long double complex, emit_long_complex);
	RUN_UNARY(ID_CTANHL, direct_ctanhl, l_values, long double complex, emit_long_complex);
	return 0;
}

int crabc_x86_64_math_complex_complete_probe(void)
{
	size_t index;
	for (index = 0; index < sizeof(rounding_modes) / sizeof(rounding_modes[0]); index++) {
		int mode = rounding_modes[index];
		if (fesetround(mode) != 0) return 80;
		if (run_float(mode) != 0) return 81;
		if (run_double(mode) != 0) return 82;
		if (run_long_double(mode) != 0) return 83;
	}
	return 0;
}

#ifndef CRABC_MATH_COMPLEX_COMPLETE_FREESTANDING
int main(void)
{
	return crabc_x86_64_math_complex_complete_probe();
}
#endif
