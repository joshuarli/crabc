/* Complete native Linux/x86-64 C++ declaration/linkage contract for math.complex. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <complex.h>
#include <float.h>
#include <math.h>

using d_real = double (*)(double _Complex);
using f_real = float (*)(float _Complex);
using l_real = long double (*)(long double _Complex);
using d_unary = double _Complex (*)(double _Complex);
using f_unary = float _Complex (*)(float _Complex);
using l_unary = long double _Complex (*)(long double _Complex);
using d_binary = double _Complex (*)(double _Complex, double _Complex);
using f_binary = float _Complex (*)(float _Complex, float _Complex);
using l_binary = long double _Complex (*)(long double _Complex, long double _Complex);

#define DIRECT(type, name) static type direct_##name = &(name)
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

static_assert(sizeof(float _Complex) == 8 && alignof(float _Complex) == 4,
	"SysV float complex storage");
static_assert(sizeof(double _Complex) == 16 && alignof(double _Complex) == 8,
	"SysV double complex storage");
static_assert(sizeof(long double) == 16 && alignof(long double) == 16 &&
	LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384,
	"SysV binary80 storage");
static_assert(sizeof(long double _Complex) == 32 &&
	alignof(long double _Complex) == 16,
	"SysV binary80 complex storage");

extern "C" int crabc_x86_64_math_complex_complete_header_probe(void)
{
	return direct_cabs == nullptr || direct_cpowl == nullptr ||
		direct_ctanhl == nullptr || direct_cprojl == nullptr;
}
