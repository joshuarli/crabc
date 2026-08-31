/* Native Linux/x86-64 C++ declaration/linkage contract for math.elementary-long-double. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <float.h>
#include <math.h>

using l_unary = long double (*)(long double);
using l_binary = long double (*)(long double, long double);
using l_ternary = long double (*)(long double, long double, long double);
using l_sincos = void (*)(long double, long double *, long double *);

#define DIRECT(type, name) static type direct_##name = &(name)
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

static_assert(sizeof(long double) == 16 && alignof(long double) == 16,
	"SysV x86-64 long double storage");
static_assert(LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384,
	"SysV x86-64 binary80 format");

extern "C" int crabc_x86_64_math_elementary_long_double_header_probe(void)
{
	return direct_acoshl == nullptr || direct_fmal == nullptr ||
		direct_powl == nullptr || direct_sincosl == nullptr ||
		direct_tanl == nullptr;
}
