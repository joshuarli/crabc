/* Project/pinned-musl C++ declaration and linkage proof for cbrt/cbrtf. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <math.h>

using double_unary_signature = double (*)(double);
using float_unary_signature = float (*)(float);

static double_unary_signature volatile direct_cbrt = &cbrt;
static float_unary_signature volatile direct_cbrtf = &cbrtf;

extern "C" int crabc_x86_64_math_cbrt_header_cxx_probe(void)
{
	return direct_cbrt(8.0) == 2.0 && direct_cbrtf(8.0f) == 2.0f ? 0 : 1;
}
