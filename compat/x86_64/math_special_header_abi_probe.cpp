/* Native Linux/x86-64 C++ declaration/linkage contract for math.special. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <float.h>
#include <math.h>

using d_unary = double (*)(double);
using f_unary = float (*)(float);
using l_unary = long double (*)(long double);
using d_binary = double (*)(double, double);
using f_binary = float (*)(float, float);
using l_binary = long double (*)(long double, long double);
using d_integer = int (*)(double);
using f_integer = int (*)(float);
using l_integer = int (*)(long double);
using d_frexp = double (*)(double, int *);
using f_frexp = float (*)(float, int *);
using l_frexp = long double (*)(long double, int *);
using d_modf = double (*)(double, double *);
using f_modf = float (*)(float, float *);
using l_modf = long double (*)(long double, long double *);
using d_remquo = double (*)(double, double, int *);
using f_remquo = float (*)(float, float, int *);
using l_remquo = long double (*)(long double, long double, int *);
using d_int_scale = double (*)(double, int);
using f_int_scale = float (*)(float, int);
using l_int_scale = long double (*)(long double, int);
using d_long_scale = double (*)(double, long);
using f_long_scale = float (*)(float, long);
using l_long_scale = long double (*)(long double, long);
using d_long = long (*)(double);
using f_long = long (*)(float);
using l_long = long (*)(long double);
using d_long_long = long long (*)(double);
using f_long_long = long long (*)(float);
using l_long_long = long long (*)(long double);
using d_order = double (*)(int, double);
using f_order = float (*)(int, float);
using d_nexttoward = double (*)(double, long double);
using f_nexttoward = float (*)(float, long double);
using d_gamma_r = double (*)(double, int *);
using f_gamma_r = float (*)(float, int *);
using l_gamma_r = long double (*)(long double, int *);
using d_nan = double (*)(const char *);
using f_nan = float (*)(const char *);
using l_nan = long double (*)(const char *);

/* Musl exports this hidden implementation name but intentionally omits it
 * from the installed header. The capability ledger names it, so this one
 * explicit declaration proves only its C ABI/linkage spelling. */
extern "C" long double __lgammal_r(long double, int *);

#define DIRECT(type, name) static type direct_##name = &(name)
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

static int *direct_signgam = &signgam;

static_assert(sizeof(long double) == 16 && alignof(long double) == 16,
	"SysV x86-64 long double storage");
static_assert(LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384,
	"SysV x86-64 binary80 format");
static_assert(sizeof(long) == 8 && sizeof(long long) == 8,
	"SysV x86-64 LP64 integer returns");

extern "C" int crabc_x86_64_math_special_header_probe(void)
{
	return direct_signgam == nullptr || direct_erf == nullptr ||
		direct_tgammal == nullptr || direct_nexttowardf == nullptr;
}
