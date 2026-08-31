/* Project/pinned-musl C++ declaration and linkage proof for fmax/fmin. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <math.h>

using double_binary_signature = double (*)(double, double);
using float_binary_signature = float (*)(float, float);

static double_binary_signature volatile direct_fmax = &fmax;
static float_binary_signature volatile direct_fmaxf = &fmaxf;
static double_binary_signature volatile direct_fmin = &fmin;
static float_binary_signature volatile direct_fminf = &fminf;

extern "C" int crabc_x86_64_math_minmax_header_cxx_probe(void)
{
	return direct_fmax(-3.5, 1.25) == 1.25 &&
		direct_fmaxf(-3.5f, 1.25f) == 1.25f &&
		direct_fmin(-3.5, 1.25) == -3.5 &&
		direct_fminf(-3.5f, 1.25f) == -3.5f ? 0 : 1;
}
