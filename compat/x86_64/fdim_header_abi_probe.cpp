/* Project/pinned-musl C++ declaration and linkage proof for fdim/fdimf. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <math.h>

using double_binary_signature = double (*)(double, double);
using float_binary_signature = float (*)(float, float);

static double_binary_signature volatile direct_fdim = &fdim;
static float_binary_signature volatile direct_fdimf = &fdimf;

extern "C" int crabc_x86_64_fdim_header_cxx_probe(void)
{
	return direct_fdim(3.5, 1.25) == 2.25 &&
		direct_fdimf(3.5f, 1.25f) == 2.25f ? 0 : 1;
}
