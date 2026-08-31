/* Project/pinned-musl C++ declaration and linkage proof for fmod/fmodf. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <math.h>

using double_binary_signature = double (*)(double, double);
using float_binary_signature = float (*)(float, float);

static double_binary_signature volatile direct_fmod = &fmod;
static float_binary_signature volatile direct_fmodf = &fmodf;

extern "C" int crabc_x86_64_math_fmod_header_cxx_probe(void)
{
	return direct_fmod(5.5, 2.0) == 1.5 &&
		direct_fmodf(5.5f, 2.0f) == 1.5f ? 0 : 1;
}
