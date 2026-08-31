/* Project/pinned-musl C++ declaration and linkage proof for fabs/copysign. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <math.h>

using double_unary_signature = double (*)(double);
using float_unary_signature = float (*)(float);
using double_binary_signature = double (*)(double, double);
using float_binary_signature = float (*)(float, float);

static double_unary_signature volatile direct_fabs = &fabs;
static float_unary_signature volatile direct_fabsf = &fabsf;
static double_binary_signature volatile direct_copysign = &copysign;
static float_binary_signature volatile direct_copysignf = &copysignf;

extern "C" int crabc_x86_64_math_bit_sign_header_cxx_probe(void)
{
	return direct_fabs(-3.5) == 3.5 && direct_fabsf(-3.5f) == 3.5f &&
		direct_copysign(3.5, -1.0) == -3.5 &&
		direct_copysignf(3.5f, -1.0f) == -3.5f ? 0 : 1;
}
