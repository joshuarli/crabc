/*
 * Native Linux/x86-64 floating-point ABI-boundary differential for the four
 * selected C math capabilities: math.elementary-long-double,
 * math.elementary-fenv-sensitive, math.special, and math.complex.
 *
 * The per-capability probes compare ordinary values, quiet NaNs, signed
 * zeros, infinities, subnormals, and exception flags. This probe covers the
 * operand encodings and caller-visible machine state they do not:
 *
 * - signaling NaNs of each precision, alone and paired with quiet NaNs so the
 *   propagated operand is visible;
 * - x87 binary80 encodings that the format admits but arithmetic never
 *   produces (pseudo-NaN, pseudo-infinity, unnormal, pseudo-denormal);
 * - after every call: the x87 control word, the x87 status word's exception,
 *   stack-fault and TOP fields, the x87 tag word, the complete MXCSR, errno,
 *   and signgam.
 *
 * A second phase calls every entry again on deterministic pseudo-random
 * finite operands (mostly of moderate magnitude, some of any exponent), so
 * each entry's ordinary algorithm paths are compared bit for bit as well.
 *
 * Every entry of the four closed symbol sets is called through its
 * installed-header function type in all four rounding modes. A callee that
 * leaves an x87 register occupied, changes precision or rounding control,
 * raises a flag in the other unit, or writes errno changes a record even when
 * its return value matches.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <complex.h>
#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#pragma STDC FENV_ACCESS ON

_Static_assert(sizeof(long double) == 16 && LDBL_MANT_DIG == 64 &&
	LDBL_MAX_EXP == 16384, "x86 binary80 storage");
_Static_assert(sizeof(long double complex) == 32, "x86 binary80 complex storage");

extern int __signgam;
/* musl declares this internal C ABI only for its own lgammal_r alias. */
long double __lgammal_r(long double, int *);

#define ERRNO_SENTINEL 0x3c3c
#define SIGNGAM_SENTINEL 0x5a5a5a5a

struct __attribute__((packed)) boundary_record {
	uint16_t function;
	uint16_t case_index;
	uint32_t rounding;
	uint16_t x87_control;
	uint16_t x87_status;
	uint16_t x87_tag;
	uint16_t kind;
	uint32_t mxcsr;
	int32_t error;
	int32_t auxiliary;
	int32_t signgam_value;
	unsigned char value[32];
};
_Static_assert(sizeof(struct boundary_record) == 64, "stable boundary record");

enum value_kind {
	KIND_FLOAT = 1, KIND_DOUBLE, KIND_LONG_DOUBLE, KIND_INT, KIND_LONG,
	KIND_LONG_LONG, KIND_FLOAT_PAIR, KIND_DOUBLE_PAIR, KIND_LONG_DOUBLE_PAIR,
};

static const int rounding_modes[] = {
	FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO,
};
#define MODE_COUNT (sizeof(rounding_modes) / sizeof(rounding_modes[0]))
#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

static float float_bits(uint32_t bits)
{
	float value;
	memcpy(&value, &bits, sizeof(value));
	return value;
}

static double double_bits(uint64_t bits)
{
	double value;
	memcpy(&value, &bits, sizeof(value));
	return value;
}

static long double binary80(uint16_t sign_exponent, uint64_t mantissa)
{
	union { long double value; unsigned char bytes[16]; } bits;
	memset(bits.bytes, 0, sizeof(bits.bytes));
	memcpy(bits.bytes, &mantissa, sizeof(mantissa));
	memcpy(bits.bytes + 8, &sign_exponent, sizeof(sign_exponent));
	return bits.value;
}

static float f_snan_pos, f_snan_neg, f_qnan, f_one;
static double d_snan_pos, d_snan_neg, d_qnan, d_one;
static long double l_snan_pos, l_snan_neg, l_qnan, l_one;
static long double l_pseudo_nan, l_pseudo_inf, l_unnormal, l_neg_unnormal;
static long double l_pseudo_denormal, l_neg_pseudo_denormal;

static void initialize_values(void)
{
	f_snan_pos = float_bits(UINT32_C(0x7fa00123));
	f_snan_neg = float_bits(UINT32_C(0xffa00321));
	f_qnan = float_bits(UINT32_C(0x7fc00456));
	f_one = 1.5f;
	d_snan_pos = double_bits(UINT64_C(0x7ff4000000000123));
	d_snan_neg = double_bits(UINT64_C(0xfff4000000000321));
	d_qnan = double_bits(UINT64_C(0x7ff8000000000456));
	d_one = 1.5;
	l_snan_pos = binary80(0x7fff, UINT64_C(0xa000000000000123));
	l_snan_neg = binary80(0xffff, UINT64_C(0xa000000000000321));
	l_qnan = binary80(0x7fff, UINT64_C(0xc000000000000456));
	l_one = 1.5L;
	l_pseudo_nan = binary80(0x7fff, UINT64_C(0x4000000000000123));
	l_pseudo_inf = binary80(0x7fff, UINT64_C(0));
	l_unnormal = binary80(0x3fff, UINT64_C(0x4000000000000000));
	l_neg_unnormal = binary80(0xc003, UINT64_C(0x6000000000000000));
	l_pseudo_denormal = binary80(0x0000, UINT64_C(0x8000000000000001));
	l_neg_pseudo_denormal = binary80(0x8000, UINT64_C(0xc000000000000000));
}

struct f_pair { float left, right; };
struct d_pair { double left, right; };
struct l_pair { long double left, right; };
struct l_triple { long double first, second, third; };

/*
 * Operand tables for the current phase. The boundary phase holds the special
 * encodings above; the dense phase holds deterministic pseudo-random finite
 * operands so each entry's ordinary paths are also compared bit for bit.
 */
#define TABLE_CAPACITY 64
static float f_unary[TABLE_CAPACITY];
static double d_unary[TABLE_CAPACITY];
static long double l_unary[TABLE_CAPACITY];
static struct f_pair f_binary[TABLE_CAPACITY];
static struct d_pair d_binary[TABLE_CAPACITY];
static struct l_pair l_binary[TABLE_CAPACITY];
static struct l_triple l_ternary[TABLE_CAPACITY];
static float complex f_complex[TABLE_CAPACITY];
static double complex d_complex[TABLE_CAPACITY];
static long double complex l_complex[TABLE_CAPACITY];
static size_t f_unary_count, d_unary_count, l_unary_count;
static size_t f_binary_count, d_binary_count, l_binary_count, l_ternary_count;
static size_t f_complex_count, d_complex_count, l_complex_count;

#define LOAD(table, ...) do { \
	const __typeof__(table[0]) loaded[] = { __VA_ARGS__ }; \
	_Static_assert(COUNT(loaded) <= TABLE_CAPACITY, "table capacity"); \
	memcpy(table, loaded, sizeof(loaded)); \
	table##_count = COUNT(loaded); \
} while (0)

static void load_boundary_tables(void)
{
	LOAD(f_unary, f_snan_pos, f_snan_neg);
	LOAD(d_unary, d_snan_pos, d_snan_neg);
	LOAD(l_unary, l_snan_pos, l_snan_neg, l_pseudo_nan, l_pseudo_inf,
		l_unnormal, l_neg_unnormal, l_pseudo_denormal, l_neg_pseudo_denormal);
	LOAD(f_binary, { f_snan_pos, f_one }, { f_one, f_snan_neg },
		{ f_qnan, f_snan_pos }, { f_snan_neg, f_qnan });
	LOAD(d_binary, { d_snan_pos, d_one }, { d_one, d_snan_neg },
		{ d_qnan, d_snan_pos }, { d_snan_neg, d_qnan });
	LOAD(l_binary, { l_snan_pos, l_one }, { l_one, l_snan_neg },
		{ l_qnan, l_snan_pos }, { l_snan_neg, l_qnan },
		{ l_pseudo_nan, l_one }, { l_one, l_pseudo_inf },
		{ l_unnormal, l_one }, { l_one, l_neg_unnormal },
		{ l_pseudo_denormal, l_one }, { l_one, l_neg_pseudo_denormal });
	l_ternary_count = 0;
	for (size_t index = 0; index < l_unary_count; index++)
		for (size_t slot = 0; slot < 3; slot++) {
			struct l_triple *triple = &l_ternary[l_ternary_count++];
			triple->first = slot == 0 ? l_unary[index] : l_one;
			triple->second = slot == 1 ? l_unary[index] : l_one;
			triple->third = slot == 2 ? l_unary[index] : l_one;
		}
	/* Each special encoding in the real and then the imaginary component,
	 * beside an ordinary or infinite partner. */
	LOAD(f_complex, CMPLXF(f_snan_pos, f_one), CMPLXF(f_one, f_snan_neg),
		CMPLXF(f_snan_pos, INFINITY), CMPLXF(INFINITY, f_snan_pos),
		CMPLXF(f_qnan, f_snan_pos), CMPLXF(f_snan_neg, f_qnan));
	LOAD(d_complex, CMPLX(d_snan_pos, d_one), CMPLX(d_one, d_snan_neg),
		CMPLX(d_snan_pos, INFINITY), CMPLX(INFINITY, d_snan_pos),
		CMPLX(d_qnan, d_snan_pos), CMPLX(d_snan_neg, d_qnan));
	LOAD(l_complex, CMPLXL(l_snan_pos, l_one), CMPLXL(l_one, l_snan_neg),
		CMPLXL(l_snan_pos, INFINITY), CMPLXL(INFINITY, l_snan_pos),
		CMPLXL(l_qnan, l_snan_pos), CMPLXL(l_snan_neg, l_qnan),
		CMPLXL(l_pseudo_nan, l_one), CMPLXL(l_one, l_pseudo_inf),
		CMPLXL(l_unnormal, l_one), CMPLXL(l_one, l_neg_unnormal),
		CMPLXL(l_pseudo_denormal, l_one), CMPLXL(l_one, l_neg_pseudo_denormal));
}

/* SplitMix64 only spreads fixed test operands; it is not an entropy source. */
static uint64_t dense_state;

static uint64_t dense_next(void)
{
	uint64_t z = (dense_state += UINT64_C(0x9e3779b97f4a7c15));
	z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
	return z ^ (z >> 31);
}

/*
 * Three of four operands have a magnitude in [2^-24, 2^24), where the
 * elementary, gamma, Bessel and complex paths do their ordinary work; the
 * rest take any finite exponent, including subnormals. Signs are random.
 */
static int dense_exponent(int bias, int maximum, int *subnormal)
{
	uint64_t bits = dense_next();
	*subnormal = 0;
	if ((bits & 3) != 0)
		return bias - 24 + (int)((bits >> 2) % 48);
	int exponent = (int)((bits >> 2) % (uint64_t)maximum);
	*subnormal = exponent == 0;
	return exponent;
}

static float dense_float(void)
{
	int subnormal;
	uint32_t exponent = (uint32_t)dense_exponent(127, 255, &subnormal);
	uint64_t bits = dense_next();
	uint32_t mantissa = (uint32_t)bits & UINT32_C(0x7fffff);
	if (subnormal && mantissa == 0) mantissa = 1;
	return float_bits((uint32_t)(bits >> 63) << 31 | exponent << 23 | mantissa);
}

static double dense_double(void)
{
	int subnormal;
	uint64_t exponent = (uint64_t)dense_exponent(1023, 2047, &subnormal);
	uint64_t bits = dense_next();
	uint64_t mantissa = bits & UINT64_C(0xfffffffffffff);
	if (subnormal && mantissa == 0) mantissa = 1;
	return double_bits((bits >> 63) << 63 | exponent << 52 | mantissa);
}

static long double dense_long_double(void)
{
	int subnormal;
	uint16_t exponent = (uint16_t)dense_exponent(16383, 32767, &subnormal);
	uint64_t bits = dense_next();
	/* Canonical binary80: the explicit integer bit is set exactly for
	 * normal numbers. */
	uint64_t mantissa = subnormal ? (bits >> 1) | 1 : bits | UINT64_C(1) << 63;
	uint16_t sign = (uint16_t)(dense_next() >> 63) << 15;
	return binary80((uint16_t)(sign | exponent), mantissa);
}

static void load_dense_tables(void)
{
	dense_state = UINT64_C(0x6372616263206d61); /* "crabc ma" */
	f_unary_count = d_unary_count = l_unary_count = TABLE_CAPACITY;
	f_binary_count = d_binary_count = l_binary_count = TABLE_CAPACITY;
	l_ternary_count = TABLE_CAPACITY;
	f_complex_count = d_complex_count = l_complex_count = TABLE_CAPACITY;
	for (size_t index = 0; index < TABLE_CAPACITY; index++) {
		f_unary[index] = dense_float();
		d_unary[index] = dense_double();
		l_unary[index] = dense_long_double();
		f_binary[index].left = dense_float();
		f_binary[index].right = dense_float();
		d_binary[index].left = dense_double();
		d_binary[index].right = dense_double();
		l_binary[index].left = dense_long_double();
		l_binary[index].right = dense_long_double();
		l_ternary[index].first = dense_long_double();
		l_ternary[index].second = dense_long_double();
		l_ternary[index].third = dense_long_double();
		f_complex[index] = CMPLXF(dense_float(), dense_float());
		d_complex[index] = CMPLX(dense_double(), dense_double());
		l_complex[index] = CMPLXL(dense_long_double(), dense_long_double());
	}
}

static int write_all(const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;

	while (length != 0) {
		ssize_t count = write(1, cursor, length);

		if (count <= 0)
			return -1;
		cursor += (size_t)count;
		length -= (size_t)count;
	}
	return 0;
}

static struct boundary_record pending;
/* Case-index bit 15 distinguishes the dense phase from the boundary phase. */
static uint16_t phase_bit;

static void prepare(uint16_t function, uint16_t index, int mode)
{
	memset(&pending, 0, sizeof(pending));
	pending.function = function;
	pending.case_index = (uint16_t)(index | phase_bit);
	pending.rounding = (uint32_t)mode;
	(void)fesetround(mode);
	(void)feclearexcept(FE_ALL_EXCEPT);
	errno = ERRNO_SENTINEL;
	signgam = __signgam = SIGNGAM_SENTINEL;
}

/*
 * Capture the caller-visible machine state before any other floating-point
 * operation. FNSTENV masks every x87 exception as a side effect, so FLDENV
 * restores the observed environment unchanged.
 */
static int finish(uint16_t kind, const void *value, size_t size, int auxiliary)
{
	struct { uint16_t control, r0, status, r1, tag, r2; uint32_t rest[4]; } x87;
	uint32_t mxcsr;

	__asm__ volatile ("fnstenv %0\n\tfldenv %0" : "=m"(x87) : : "memory");
	__asm__ volatile ("stmxcsr %0" : "=m"(mxcsr) : : "memory");
	pending.error = errno;
	pending.signgam_value = signgam;
	pending.x87_control = x87.control;
	/* Keep exception, stack-fault and TOP fields; condition codes are not
	 * part of the calling convention. */
	pending.x87_status = (uint16_t)(x87.status & 0x38ff);
	pending.x87_tag = x87.tag;
	pending.mxcsr = mxcsr;
	pending.kind = kind;
	pending.auxiliary = auxiliary;
	memcpy(pending.value, value, size);
	if (signgam != __signgam)
		return -1;
	return write_all(&pending, sizeof(pending));
}

static int finish_float(float value, int auxiliary)
{
	return finish(KIND_FLOAT, &value, sizeof(value), auxiliary);
}

static int finish_double(double value, int auxiliary)
{
	return finish(KIND_DOUBLE, &value, sizeof(value), auxiliary);
}

static int finish_long_double(long double value, int auxiliary)
{
	return finish(KIND_LONG_DOUBLE, &value, 10, auxiliary);
}

static int finish_long_double_pair(long double first, long double second)
{
	unsigned char bytes[20];
	memcpy(bytes, &first, 10);
	memcpy(bytes + 10, &second, 10);
	return finish(KIND_LONG_DOUBLE_PAIR, bytes, sizeof(bytes), 0);
}

typedef float (*f_f)(float);
typedef double (*d_d)(double);
typedef long double (*l_l)(long double);
typedef float (*f_ff)(float, float);
typedef double (*d_dd)(double, double);
typedef long double (*l_ll)(long double, long double);
typedef long double (*l_lll)(long double, long double, long double);
typedef float (*f_fl)(float, long double);
typedef double (*d_dl)(double, long double);
typedef int (*i_f)(float);
typedef int (*i_d)(double);
typedef int (*i_l)(long double);
typedef long (*lo_f)(float);
typedef long (*lo_d)(double);
typedef long (*lo_l)(long double);
typedef long long (*ll_f)(float);
typedef long long (*ll_d)(double);
typedef long long (*ll_l)(long double);
typedef float (*f_fi)(float, int);
typedef double (*d_di)(double, int);
typedef long double (*l_li)(long double, int);
typedef float (*f_flo)(float, long);
typedef double (*d_dlo)(double, long);
typedef long double (*l_llo)(long double, long);
typedef float (*f_fip)(float, int *);
typedef double (*d_dip)(double, int *);
typedef long double (*l_lip)(long double, int *);
typedef float (*f_ffp)(float, float *);
typedef double (*d_ddp)(double, double *);
typedef long double (*l_llp)(long double, long double *);
typedef float (*f_ffip)(float, float, int *);
typedef double (*d_ddip)(double, double, int *);
typedef long double (*l_llip)(long double, long double, int *);
typedef float (*f_if)(int, float);
typedef double (*d_id)(int, double);
typedef void (*v_lpp)(long double, long double *, long double *);
typedef float (*f_s)(const char *);
typedef double (*d_s)(const char *);
typedef long double (*l_s)(const char *);
typedef float (*f_cf)(float complex);
typedef double (*d_cd)(double complex);
typedef long double (*l_cl)(long double complex);
typedef float complex (*cf_cf)(float complex);
typedef double complex (*cd_cd)(double complex);
typedef long double complex (*cl_cl)(long double complex);
typedef float complex (*cf_cfcf)(float complex, float complex);
typedef double complex (*cd_cdcd)(double complex, double complex);
typedef long double complex (*cl_clcl)(long double complex, long double complex);

/* One function pointer per closed-set entry keeps every call a real
 * installed-ABI call rather than a builtin expansion. */
#define ENTRY(type, name) static type volatile direct_##name = (name)

/* math.elementary-long-double (35) */
ENTRY(l_l, acoshl); ENTRY(l_l, acosl); ENTRY(l_l, asinhl); ENTRY(l_l, asinl);
ENTRY(l_ll, atan2l); ENTRY(l_l, atanhl); ENTRY(l_l, atanl); ENTRY(l_l, cbrtl);
ENTRY(l_l, ceill); ENTRY(l_ll, copysignl); ENTRY(l_l, coshl); ENTRY(l_l, cosl);
ENTRY(l_l, exp2l); ENTRY(l_l, expl); ENTRY(l_l, expm1l); ENTRY(l_l, fabsl);
ENTRY(l_l, floorl); ENTRY(l_lll, fmal); ENTRY(l_ll, fmaxl); ENTRY(l_ll, fminl);
ENTRY(l_ll, fmodl); ENTRY(l_ll, hypotl); ENTRY(l_l, log10l); ENTRY(l_l, log1pl);
ENTRY(l_l, log2l); ENTRY(l_l, logl); ENTRY(l_ll, powl); ENTRY(l_l, roundl);
ENTRY(v_lpp, sincosl); ENTRY(l_l, sinhl); ENTRY(l_l, sinl); ENTRY(l_l, sqrtl);
ENTRY(l_l, tanhl); ENTRY(l_l, tanl); ENTRY(l_l, truncl);

/* math.elementary-fenv-sensitive (15) */
ENTRY(d_d, exp10); ENTRY(f_f, exp10f); ENTRY(l_l, exp10l);
ENTRY(d_dd, fdim); ENTRY(f_ff, fdimf); ENTRY(l_ll, fdiml);
ENTRY(d_d, nearbyint); ENTRY(f_f, nearbyintf); ENTRY(l_l, nearbyintl);
ENTRY(d_d, pow10); ENTRY(f_f, pow10f); ENTRY(l_l, pow10l);
ENTRY(d_d, rint); ENTRY(f_f, rintf); ENTRY(l_l, rintl);

/* math.special (90) */
ENTRY(i_d, __fpclassify); ENTRY(i_f, __fpclassifyf); ENTRY(i_l, __fpclassifyl);
ENTRY(l_lip, __lgammal_r); ENTRY(i_d, __signbit); ENTRY(i_f, __signbitf);
ENTRY(i_l, __signbitl); ENTRY(d_dd, drem); ENTRY(f_ff, dremf);
ENTRY(d_d, erf); ENTRY(d_d, erfc); ENTRY(f_f, erfcf); ENTRY(l_l, erfcl);
ENTRY(f_f, erff); ENTRY(l_l, erfl); ENTRY(i_d, finite); ENTRY(i_f, finitef);
ENTRY(d_dip, frexp); ENTRY(f_fip, frexpf); ENTRY(l_lip, frexpl);
ENTRY(i_d, ilogb); ENTRY(i_f, ilogbf); ENTRY(i_l, ilogbl);
ENTRY(d_d, j0); ENTRY(f_f, j0f); ENTRY(d_d, j1); ENTRY(f_f, j1f);
ENTRY(d_id, jn); ENTRY(f_if, jnf);
ENTRY(d_di, ldexp); ENTRY(f_fi, ldexpf); ENTRY(l_li, ldexpl);
ENTRY(d_d, lgamma); ENTRY(d_dip, lgamma_r); ENTRY(f_f, lgammaf);
ENTRY(f_fip, lgammaf_r); ENTRY(l_l, lgammal); ENTRY(l_lip, lgammal_r);
ENTRY(ll_d, llrint); ENTRY(ll_f, llrintf); ENTRY(ll_l, llrintl);
ENTRY(ll_d, llround); ENTRY(ll_f, llroundf); ENTRY(ll_l, llroundl);
ENTRY(d_d, logb); ENTRY(f_f, logbf); ENTRY(l_l, logbl);
ENTRY(lo_d, lrint); ENTRY(lo_f, lrintf); ENTRY(lo_l, lrintl);
ENTRY(lo_d, lround); ENTRY(lo_f, lroundf); ENTRY(lo_l, lroundl);
ENTRY(d_ddp, modf); ENTRY(f_ffp, modff); ENTRY(l_llp, modfl);
ENTRY(d_s, nan); ENTRY(f_s, nanf); ENTRY(l_s, nanl);
ENTRY(d_dd, nextafter); ENTRY(f_ff, nextafterf); ENTRY(l_ll, nextafterl);
ENTRY(d_dl, nexttoward); ENTRY(f_fl, nexttowardf); ENTRY(l_ll, nexttowardl);
ENTRY(d_dd, remainder); ENTRY(f_ff, remainderf); ENTRY(l_ll, remainderl);
ENTRY(d_ddip, remquo); ENTRY(f_ffip, remquof); ENTRY(l_llip, remquol);
ENTRY(d_dd, scalb); ENTRY(f_ff, scalbf);
ENTRY(d_dlo, scalbln); ENTRY(f_flo, scalblnf); ENTRY(l_llo, scalblnl);
ENTRY(d_di, scalbn); ENTRY(f_fi, scalbnf); ENTRY(l_li, scalbnl);
ENTRY(d_d, significand); ENTRY(f_f, significandf);
ENTRY(d_d, tgamma); ENTRY(f_f, tgammaf); ENTRY(l_l, tgammal);
ENTRY(d_d, y0); ENTRY(f_f, y0f); ENTRY(d_d, y1); ENTRY(f_f, y1f);
ENTRY(d_id, yn); ENTRY(f_if, ynf);

/* math.complex (66) */
ENTRY(d_cd, cabs); ENTRY(f_cf, cabsf); ENTRY(l_cl, cabsl);
ENTRY(cd_cd, cacos); ENTRY(cf_cf, cacosf); ENTRY(cl_cl, cacosl);
ENTRY(cd_cd, cacosh); ENTRY(cf_cf, cacoshf); ENTRY(cl_cl, cacoshl);
ENTRY(d_cd, carg); ENTRY(f_cf, cargf); ENTRY(l_cl, cargl);
ENTRY(cd_cd, casin); ENTRY(cf_cf, casinf); ENTRY(cl_cl, casinl);
ENTRY(cd_cd, casinh); ENTRY(cf_cf, casinhf); ENTRY(cl_cl, casinhl);
ENTRY(cd_cd, catan); ENTRY(cf_cf, catanf); ENTRY(cl_cl, catanl);
ENTRY(cd_cd, catanh); ENTRY(cf_cf, catanhf); ENTRY(cl_cl, catanhl);
ENTRY(cd_cd, ccos); ENTRY(cf_cf, ccosf); ENTRY(cl_cl, ccosl);
ENTRY(cd_cd, ccosh); ENTRY(cf_cf, ccoshf); ENTRY(cl_cl, ccoshl);
ENTRY(cd_cd, cexp); ENTRY(cf_cf, cexpf); ENTRY(cl_cl, cexpl);
ENTRY(d_cd, cimag); ENTRY(f_cf, cimagf); ENTRY(l_cl, cimagl);
ENTRY(cd_cd, clog); ENTRY(cf_cf, clogf); ENTRY(cl_cl, clogl);
ENTRY(cd_cd, conj); ENTRY(cf_cf, conjf); ENTRY(cl_cl, conjl);
ENTRY(cd_cdcd, cpow); ENTRY(cf_cfcf, cpowf); ENTRY(cl_clcl, cpowl);
ENTRY(cd_cd, cproj); ENTRY(cf_cf, cprojf); ENTRY(cl_cl, cprojl);
ENTRY(d_cd, creal); ENTRY(f_cf, crealf); ENTRY(l_cl, creall);
ENTRY(cd_cd, csin); ENTRY(cf_cf, csinf); ENTRY(cl_cl, csinl);
ENTRY(cd_cd, csinh); ENTRY(cf_cf, csinhf); ENTRY(cl_cl, csinhl);
ENTRY(cd_cd, csqrt); ENTRY(cf_cf, csqrtf); ENTRY(cl_cl, csqrtl);
ENTRY(cd_cd, ctan); ENTRY(cf_cf, ctanf); ENTRY(cl_cl, ctanl);
ENTRY(cd_cd, ctanh); ENTRY(cf_cf, ctanhf); ENTRY(cl_cl, ctanhl);
#undef ENTRY

/* Each runner loops over rounding modes and one operand table. The record's
 * function identifier is the entry's position in this file's call order. */
static uint16_t function_id;

#define FOR_CASES(values) \
	for (size_t mode = 0; mode < MODE_COUNT; mode++) \
		for (size_t index = 0; index < values##_count; index++)
#define PREPARE() prepare(function_id, (uint16_t)index, rounding_modes[mode])

static int run_f_f(f_f function)
{
	const float *values = f_unary; size_t values_count = f_unary_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		float result = function(values[index]);
		if (finish_float(result, 0) != 0) return -1;
	}
	return 0;
}

static int run_d_d(d_d function)
{
	const double *values = d_unary; size_t values_count = d_unary_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		double result = function(values[index]);
		if (finish_double(result, 0) != 0) return -1;
	}
	return 0;
}

static int run_l_l(l_l function)
{
	const long double *values = l_unary; size_t values_count = l_unary_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		long double result = function(values[index]);
		if (finish_long_double(result, 0) != 0) return -1;
	}
	return 0;
}

static int run_f_ff(f_ff function)
{
	const struct f_pair *values = f_binary; size_t values_count = f_binary_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		float result = function(values[index].left, values[index].right);
		if (finish_float(result, 0) != 0) return -1;
	}
	return 0;
}

static int run_d_dd(d_dd function)
{
	const struct d_pair *values = d_binary; size_t values_count = d_binary_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		double result = function(values[index].left, values[index].right);
		if (finish_double(result, 0) != 0) return -1;
	}
	return 0;
}

static int run_l_ll(l_ll function)
{
	const struct l_pair *values = l_binary; size_t values_count = l_binary_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		long double result = function(values[index].left, values[index].right);
		if (finish_long_double(result, 0) != 0) return -1;
	}
	return 0;
}

static int run_l_lll(l_lll function)
{
	const struct l_triple *values = l_ternary; size_t values_count = l_ternary_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		long double result = function(values[index].first, values[index].second,
			values[index].third);
		if (finish_long_double(result, 0) != 0) return -1;
	}
	return 0;
}

/* nexttoward's second operand is binary80: vary each operand separately. */
#define RUN_TOWARD(name, type, values_init, one, emit) \
static int name(type (*function)(type, long double)) \
{ \
	const type *values = values_init; size_t values_count = values_init##_count; \
	const long double *longs = l_unary; size_t longs_count = l_unary_count; \
	function_id++; \
	FOR_CASES(values) { \
		PREPARE(); \
		type result = function(values[index], l_one); \
		if (emit(result, 0) != 0) return -1; \
		prepare(function_id, (uint16_t)(0x100 + index), rounding_modes[mode]); \
		result = function(values[index], l_snan_neg); \
		if (emit(result, 0) != 0) return -1; \
	} \
	FOR_CASES(longs) { \
		prepare(function_id, (uint16_t)(0x200 + index), rounding_modes[mode]); \
		type result = function(one, longs[index]); \
		if (emit(result, 0) != 0) return -1; \
	} \
	return 0; \
}
RUN_TOWARD(run_d_dl, double, d_unary, d_one, finish_double)
RUN_TOWARD(run_f_fl, float, f_unary, f_one, finish_float)
#undef RUN_TOWARD

#define RUN_INTEGER(name, argument, values_init, kind, result_type) \
static int name(result_type (*function)(argument)) \
{ \
	const argument *values = values_init; size_t values_count = values_init##_count; \
	function_id++; \
	FOR_CASES(values) { \
		PREPARE(); \
		result_type result = function(values[index]); \
		if (finish(kind, &result, sizeof(result), 0) != 0) return -1; \
	} \
	return 0; \
}
RUN_INTEGER(run_i_f, float, f_unary, KIND_INT, int)
RUN_INTEGER(run_i_d, double, d_unary, KIND_INT, int)
RUN_INTEGER(run_i_l, long double, l_unary, KIND_INT, int)
RUN_INTEGER(run_lo_f, float, f_unary, KIND_LONG, long)
RUN_INTEGER(run_lo_d, double, d_unary, KIND_LONG, long)
RUN_INTEGER(run_lo_l, long double, l_unary, KIND_LONG, long)
RUN_INTEGER(run_ll_f, float, f_unary, KIND_LONG_LONG, long long)
RUN_INTEGER(run_ll_d, double, d_unary, KIND_LONG_LONG, long long)
RUN_INTEGER(run_ll_l, long double, l_unary, KIND_LONG_LONG, long long)
#undef RUN_INTEGER

/* Scaling by an integer: (x, 3). */
#define RUN_SCALE(name, type, integer, values_init, emit) \
static int name(type (*function)(type, integer)) \
{ \
	const type *values = values_init; size_t values_count = values_init##_count; \
	function_id++; \
	FOR_CASES(values) { \
		PREPARE(); \
		type result = function(values[index], 3); \
		if (emit(result, 0) != 0) return -1; \
	} \
	return 0; \
}
RUN_SCALE(run_f_fi, float, int, f_unary, finish_float)
RUN_SCALE(run_d_di, double, int, d_unary, finish_double)
RUN_SCALE(run_l_li, long double, int, l_unary, finish_long_double)
RUN_SCALE(run_f_flo, float, long, f_unary, finish_float)
RUN_SCALE(run_d_dlo, double, long, d_unary, finish_double)
RUN_SCALE(run_l_llo, long double, long, l_unary, finish_long_double)
#undef RUN_SCALE

/* Integer out-parameter: frexp exponents and lgamma_r signs. */
#define RUN_OUT_INT(name, type, values_init, emit) \
static int name(type (*function)(type, int *)) \
{ \
	const type *values = values_init; size_t values_count = values_init##_count; \
	function_id++; \
	FOR_CASES(values) { \
		int out = 0x77777777; \
		PREPARE(); \
		type result = function(values[index], &out); \
		if (emit(result, out) != 0) return -1; \
	} \
	return 0; \
}
RUN_OUT_INT(run_f_fip, float, f_unary, finish_float)
RUN_OUT_INT(run_d_dip, double, d_unary, finish_double)
RUN_OUT_INT(run_l_lip, long double, l_unary, finish_long_double)
#undef RUN_OUT_INT

/* Order n: jn/yn(2, x). */
#define RUN_ORDER(name, type, values_init, emit) \
static int name(type (*function)(int, type)) \
{ \
	const type *values = values_init; size_t values_count = values_init##_count; \
	function_id++; \
	FOR_CASES(values) { \
		PREPARE(); \
		type result = function(2, values[index]); \
		if (emit(result, 0) != 0) return -1; \
	} \
	return 0; \
}
RUN_ORDER(run_f_if, float, f_unary, finish_float)
RUN_ORDER(run_d_id, double, d_unary, finish_double)
#undef RUN_ORDER

static int run_f_ffp(f_ffp function)
{
	const float *values = f_unary; size_t values_count = f_unary_count;
	function_id++;
	FOR_CASES(values) {
		float integral = 7.0f;
		PREPARE();
		float fraction = function(values[index], &integral);
		float both[2] = { fraction, integral };
		if (finish(KIND_FLOAT_PAIR, both, sizeof(both), 0) != 0) return -1;
	}
	return 0;
}

static int run_d_ddp(d_ddp function)
{
	const double *values = d_unary; size_t values_count = d_unary_count;
	function_id++;
	FOR_CASES(values) {
		double integral = 7.0;
		PREPARE();
		double fraction = function(values[index], &integral);
		double both[2] = { fraction, integral };
		if (finish(KIND_DOUBLE_PAIR, both, sizeof(both), 0) != 0) return -1;
	}
	return 0;
}

static int run_l_llp(l_llp function)
{
	const long double *values = l_unary; size_t values_count = l_unary_count;
	function_id++;
	FOR_CASES(values) {
		long double integral = 7.0L;
		PREPARE();
		long double fraction = function(values[index], &integral);
		if (finish_long_double_pair(fraction, integral) != 0) return -1;
	}
	return 0;
}

#define RUN_REMQUO(name, type, pair, values_init, emit) \
static int name(type (*function)(type, type, int *)) \
{ \
	const struct pair *values = values_init; size_t values_count = values_init##_count; \
	function_id++; \
	FOR_CASES(values) { \
		int quotient = 0x77777777; \
		PREPARE(); \
		type result = function(values[index].left, values[index].right, &quotient); \
		if (emit(result, quotient) != 0) return -1; \
	} \
	return 0; \
}
RUN_REMQUO(run_f_ffip, float, f_pair, f_binary, finish_float)
RUN_REMQUO(run_d_ddip, double, d_pair, d_binary, finish_double)
RUN_REMQUO(run_l_llip, long double, l_pair, l_binary, finish_long_double)
#undef RUN_REMQUO

static int run_sincosl(void)
{
	const long double *values = l_unary; size_t values_count = l_unary_count;
	function_id++;
	FOR_CASES(values) {
		long double sine = 7.0L, cosine = 7.0L;
		PREPARE();
		direct_sincosl(values[index], &sine, &cosine);
		if (finish_long_double_pair(sine, cosine) != 0) return -1;
	}
	return 0;
}

/* nan/nanf/nanl take no floating operand; they still must leave the
 * caller's machine state and errno alone. */
static const char *const nan_tags[] = { "", "0x5", "invalid" };
static const size_t nan_tags_count = COUNT(nan_tags);

#define RUN_NAN(name, type, emit) \
static int name(type (*function)(const char *)) \
{ \
	function_id++; \
	FOR_CASES(nan_tags) { \
		PREPARE(); \
		type result = function(nan_tags[index]); \
		if (emit(result, 0) != 0) return -1; \
	} \
	return 0; \
}
RUN_NAN(run_f_s, float, finish_float)
RUN_NAN(run_d_s, double, finish_double)
RUN_NAN(run_l_s, long double, finish_long_double)
#undef RUN_NAN

static int run_f_cf(f_cf function)
{
	const float complex *values = f_complex; size_t values_count = f_complex_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		float result = function(values[index]);
		if (finish_float(result, 0) != 0) return -1;
	}
	return 0;
}

static int run_d_cd(d_cd function)
{
	const double complex *values = d_complex; size_t values_count = d_complex_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		double result = function(values[index]);
		if (finish_double(result, 0) != 0) return -1;
	}
	return 0;
}

static int run_l_cl(l_cl function)
{
	const long double complex *values = l_complex; size_t values_count = l_complex_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		long double result = function(values[index]);
		if (finish_long_double(result, 0) != 0) return -1;
	}
	return 0;
}

static int emit_float_complex(float complex value)
{
	float parts[2];
	memcpy(parts, &value, sizeof(parts));
	return finish(KIND_FLOAT_PAIR, parts, sizeof(parts), 0);
}

static int emit_double_complex(double complex value)
{
	double parts[2];
	memcpy(parts, &value, sizeof(parts));
	return finish(KIND_DOUBLE_PAIR, parts, sizeof(parts), 0);
}

static int emit_long_double_complex(long double complex value)
{
	long double parts[2];
	memcpy(parts, &value, sizeof(parts));
	return finish_long_double_pair(parts[0], parts[1]);
}

static int run_cf_cf(cf_cf function)
{
	const float complex *values = f_complex; size_t values_count = f_complex_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		float complex result = function(values[index]);
		if (emit_float_complex(result) != 0) return -1;
	}
	return 0;
}

static int run_cd_cd(cd_cd function)
{
	const double complex *values = d_complex; size_t values_count = d_complex_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		double complex result = function(values[index]);
		if (emit_double_complex(result) != 0) return -1;
	}
	return 0;
}

static int run_cl_cl(cl_cl function)
{
	const long double complex *values = l_complex; size_t values_count = l_complex_count;
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		long double complex result = function(values[index]);
		if (emit_long_double_complex(result) != 0) return -1;
	}
	return 0;
}

static int run_cf_cfcf(cf_cfcf function)
{
	const float complex *values = f_complex; size_t values_count = f_complex_count;
	const float complex ordinary = CMPLXF(1.5f, 0.5f);
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		float complex result = function(values[index], ordinary);
		if (emit_float_complex(result) != 0) return -1;
		prepare(function_id, (uint16_t)(0x100 + index), rounding_modes[mode]);
		result = function(ordinary, values[index]);
		if (emit_float_complex(result) != 0) return -1;
	}
	return 0;
}

static int run_cd_cdcd(cd_cdcd function)
{
	const double complex *values = d_complex; size_t values_count = d_complex_count;
	const double complex ordinary = CMPLX(1.5, 0.5);
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		double complex result = function(values[index], ordinary);
		if (emit_double_complex(result) != 0) return -1;
		prepare(function_id, (uint16_t)(0x100 + index), rounding_modes[mode]);
		result = function(ordinary, values[index]);
		if (emit_double_complex(result) != 0) return -1;
	}
	return 0;
}

static int run_cl_clcl(cl_clcl function)
{
	const long double complex *values = l_complex; size_t values_count = l_complex_count;
	const long double complex ordinary = CMPLXL(1.5L, 0.5L);
	function_id++;
	FOR_CASES(values) {
		PREPARE();
		long double complex result = function(values[index], ordinary);
		if (emit_long_double_complex(result) != 0) return -1;
		prepare(function_id, (uint16_t)(0x100 + index), rounding_modes[mode]);
		result = function(ordinary, values[index]);
		if (emit_long_double_complex(result) != 0) return -1;
	}
	return 0;
}

/* Run every closed-set entry once, in this file's order. */
static int run_all_entries(void)
{
	function_id = 0;
	return
		/* math.elementary-long-double */
		run_l_l(direct_acoshl) || run_l_l(direct_acosl) ||
		run_l_l(direct_asinhl) || run_l_l(direct_asinl) ||
		run_l_ll(direct_atan2l) || run_l_l(direct_atanhl) ||
		run_l_l(direct_atanl) || run_l_l(direct_cbrtl) ||
		run_l_l(direct_ceill) || run_l_ll(direct_copysignl) ||
		run_l_l(direct_coshl) || run_l_l(direct_cosl) ||
		run_l_l(direct_exp2l) || run_l_l(direct_expl) ||
		run_l_l(direct_expm1l) || run_l_l(direct_fabsl) ||
		run_l_l(direct_floorl) || run_l_lll(direct_fmal) ||
		run_l_ll(direct_fmaxl) || run_l_ll(direct_fminl) ||
		run_l_ll(direct_fmodl) || run_l_ll(direct_hypotl) ||
		run_l_l(direct_log10l) || run_l_l(direct_log1pl) ||
		run_l_l(direct_log2l) || run_l_l(direct_logl) ||
		run_l_ll(direct_powl) || run_l_l(direct_roundl) ||
		run_sincosl() || run_l_l(direct_sinhl) || run_l_l(direct_sinl) ||
		run_l_l(direct_sqrtl) || run_l_l(direct_tanhl) ||
		run_l_l(direct_tanl) || run_l_l(direct_truncl) ||
		/* math.elementary-fenv-sensitive */
		run_d_d(direct_exp10) || run_f_f(direct_exp10f) ||
		run_l_l(direct_exp10l) || run_d_dd(direct_fdim) ||
		run_f_ff(direct_fdimf) || run_l_ll(direct_fdiml) ||
		run_d_d(direct_nearbyint) || run_f_f(direct_nearbyintf) ||
		run_l_l(direct_nearbyintl) || run_d_d(direct_pow10) ||
		run_f_f(direct_pow10f) || run_l_l(direct_pow10l) ||
		run_d_d(direct_rint) || run_f_f(direct_rintf) ||
		run_l_l(direct_rintl) ||
		/* math.special */
		run_i_d(direct___fpclassify) || run_i_f(direct___fpclassifyf) ||
		run_i_l(direct___fpclassifyl) || run_l_lip(direct___lgammal_r) ||
		run_i_d(direct___signbit) || run_i_f(direct___signbitf) ||
		run_i_l(direct___signbitl) || run_d_dd(direct_drem) ||
		run_f_ff(direct_dremf) || run_d_d(direct_erf) ||
		run_d_d(direct_erfc) || run_f_f(direct_erfcf) ||
		run_l_l(direct_erfcl) || run_f_f(direct_erff) ||
		run_l_l(direct_erfl) || run_i_d(direct_finite) ||
		run_i_f(direct_finitef) || run_d_dip(direct_frexp) ||
		run_f_fip(direct_frexpf) || run_l_lip(direct_frexpl) ||
		run_i_d(direct_ilogb) || run_i_f(direct_ilogbf) ||
		run_i_l(direct_ilogbl) || run_d_d(direct_j0) ||
		run_f_f(direct_j0f) || run_d_d(direct_j1) || run_f_f(direct_j1f) ||
		run_d_id(direct_jn) || run_f_if(direct_jnf) ||
		run_d_di(direct_ldexp) || run_f_fi(direct_ldexpf) ||
		run_l_li(direct_ldexpl) || run_d_d(direct_lgamma) ||
		run_d_dip(direct_lgamma_r) || run_f_f(direct_lgammaf) ||
		run_f_fip(direct_lgammaf_r) || run_l_l(direct_lgammal) ||
		run_l_lip(direct_lgammal_r) || run_ll_d(direct_llrint) ||
		run_ll_f(direct_llrintf) || run_ll_l(direct_llrintl) ||
		run_ll_d(direct_llround) || run_ll_f(direct_llroundf) ||
		run_ll_l(direct_llroundl) || run_d_d(direct_logb) ||
		run_f_f(direct_logbf) || run_l_l(direct_logbl) ||
		run_lo_d(direct_lrint) || run_lo_f(direct_lrintf) ||
		run_lo_l(direct_lrintl) || run_lo_d(direct_lround) ||
		run_lo_f(direct_lroundf) || run_lo_l(direct_lroundl) ||
		run_d_ddp(direct_modf) || run_f_ffp(direct_modff) ||
		run_l_llp(direct_modfl) || run_d_s(direct_nan) ||
		run_f_s(direct_nanf) || run_l_s(direct_nanl) ||
		run_d_dd(direct_nextafter) || run_f_ff(direct_nextafterf) ||
		run_l_ll(direct_nextafterl) || run_d_dl(direct_nexttoward) ||
		run_f_fl(direct_nexttowardf) || run_l_ll(direct_nexttowardl) ||
		run_d_dd(direct_remainder) || run_f_ff(direct_remainderf) ||
		run_l_ll(direct_remainderl) || run_d_ddip(direct_remquo) ||
		run_f_ffip(direct_remquof) || run_l_llip(direct_remquol) ||
		run_d_dd(direct_scalb) || run_f_ff(direct_scalbf) ||
		run_d_dlo(direct_scalbln) || run_f_flo(direct_scalblnf) ||
		run_l_llo(direct_scalblnl) || run_d_di(direct_scalbn) ||
		run_f_fi(direct_scalbnf) || run_l_li(direct_scalbnl) ||
		run_d_d(direct_significand) || run_f_f(direct_significandf) ||
		run_d_d(direct_tgamma) || run_f_f(direct_tgammaf) ||
		run_l_l(direct_tgammal) || run_d_d(direct_y0) ||
		run_f_f(direct_y0f) || run_d_d(direct_y1) || run_f_f(direct_y1f) ||
		run_d_id(direct_yn) || run_f_if(direct_ynf) ||
		/* math.complex */
		run_d_cd(direct_cabs) || run_f_cf(direct_cabsf) ||
		run_l_cl(direct_cabsl) || run_cd_cd(direct_cacos) ||
		run_cf_cf(direct_cacosf) || run_cl_cl(direct_cacosl) ||
		run_cd_cd(direct_cacosh) || run_cf_cf(direct_cacoshf) ||
		run_cl_cl(direct_cacoshl) || run_d_cd(direct_carg) ||
		run_f_cf(direct_cargf) || run_l_cl(direct_cargl) ||
		run_cd_cd(direct_casin) || run_cf_cf(direct_casinf) ||
		run_cl_cl(direct_casinl) || run_cd_cd(direct_casinh) ||
		run_cf_cf(direct_casinhf) || run_cl_cl(direct_casinhl) ||
		run_cd_cd(direct_catan) || run_cf_cf(direct_catanf) ||
		run_cl_cl(direct_catanl) || run_cd_cd(direct_catanh) ||
		run_cf_cf(direct_catanhf) || run_cl_cl(direct_catanhl) ||
		run_cd_cd(direct_ccos) || run_cf_cf(direct_ccosf) ||
		run_cl_cl(direct_ccosl) || run_cd_cd(direct_ccosh) ||
		run_cf_cf(direct_ccoshf) || run_cl_cl(direct_ccoshl) ||
		run_cd_cd(direct_cexp) || run_cf_cf(direct_cexpf) ||
		run_cl_cl(direct_cexpl) || run_d_cd(direct_cimag) ||
		run_f_cf(direct_cimagf) || run_l_cl(direct_cimagl) ||
		run_cd_cd(direct_clog) || run_cf_cf(direct_clogf) ||
		run_cl_cl(direct_clogl) || run_cd_cd(direct_conj) ||
		run_cf_cf(direct_conjf) || run_cl_cl(direct_conjl) ||
		run_cd_cdcd(direct_cpow) || run_cf_cfcf(direct_cpowf) ||
		run_cl_clcl(direct_cpowl) || run_cd_cd(direct_cproj) ||
		run_cf_cf(direct_cprojf) || run_cl_cl(direct_cprojl) ||
		run_d_cd(direct_creal) || run_f_cf(direct_crealf) ||
		run_l_cl(direct_creall) || run_cd_cd(direct_csin) ||
		run_cf_cf(direct_csinf) || run_cl_cl(direct_csinl) ||
		run_cd_cd(direct_csinh) || run_cf_cf(direct_csinhf) ||
		run_cl_cl(direct_csinhl) || run_cd_cd(direct_csqrt) ||
		run_cf_cf(direct_csqrtf) || run_cl_cl(direct_csqrtl) ||
		run_cd_cd(direct_ctan) || run_cf_cf(direct_ctanf) ||
		run_cl_cl(direct_ctanl) || run_cd_cd(direct_ctanh) ||
		run_cf_cf(direct_ctanhf) || run_cl_cl(direct_ctanhl) ||
		function_id != 206;
}

int crabc_x86_64_math_abi_boundary_probe(void)
{
	fenv_t caller;
	int status;

	if (fegetenv(&caller) != 0)
		return 1;
	initialize_values();
	load_boundary_tables();
	phase_bit = 0;
	status = run_all_entries();
	if (status == 0) {
		load_dense_tables();
		phase_bit = 0x8000;
		status = run_all_entries();
	}
	if (fesetenv(&caller) != 0)
		return 2;
	return status == 0 ? 0 : 3;
}

#ifndef CRABC_MATH_ABI_BOUNDARY_FREESTANDING
int main(void)
{
	return crabc_x86_64_math_abi_boundary_probe();
}
#endif
