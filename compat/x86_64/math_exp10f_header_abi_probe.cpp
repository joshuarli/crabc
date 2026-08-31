/* Project/pinned-musl C++ declaration and linkage proof for exp10f/pow10f. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <math.h>

using float_unary_signature = float (*)(float);

static float_unary_signature volatile direct_exp10f = &exp10f;
static float_unary_signature volatile direct_pow10f = &pow10f;

extern "C" int crabc_x86_64_math_exp10f_header_cxx_probe(void)
{
	return direct_exp10f(0.0f) == 1.0f && direct_pow10f(0.0f) == 1.0f &&
		direct_exp10f(1.0f) == 10.0f && direct_pow10f(1.0f) == 10.0f ? 0 : 1;
}
