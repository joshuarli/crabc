/* Project/pinned-musl C++ declaration and linkage proof for sinh/sinhf. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <math.h>

using double_unary_signature = double (*)(double);
using float_unary_signature = float (*)(float);

static double_unary_signature volatile direct_sinh = &sinh;
static float_unary_signature volatile direct_sinhf = &sinhf;

extern "C" int crabc_x86_64_math_sinh_header_cxx_probe(void)
{
	return direct_sinh(0.0) == 0.0 && direct_sinhf(0.0f) == 0.0f &&
		direct_sinh(1.0) > 1.0 && direct_sinhf(1.0f) > 1.0f ? 0 : 1;
}
