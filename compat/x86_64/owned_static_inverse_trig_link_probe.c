/*
 * Installed Linux/x86-64 owned-static inverse-trigonometry link regression.
 *
 * The owned sysroot driver must resolve these eight binary32/binary64 C ABI
 * entries from its installed libc archive.  Volatile function pointers retain
 * ordinary C calls under `-fno-builtin`, so this probe cannot be satisfied by
 * compiler intrinsics or an ambient libm at the final link.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <math.h>

typedef double (*double_unary_function)(double);
typedef double (*double_binary_function)(double, double);
typedef float (*float_unary_function)(float);
typedef float (*float_binary_function)(float, float);

static double_unary_function volatile direct_asin = (asin);
static double_unary_function volatile direct_acos = (acos);
static double_unary_function volatile direct_atan = (atan);
static double_binary_function volatile direct_atan2 = (atan2);
static float_unary_function volatile direct_asinf = (asinf);
static float_unary_function volatile direct_acosf = (acosf);
static float_unary_function volatile direct_atanf = (atanf);
static float_binary_function volatile direct_atan2f = (atan2f);

int main(void)
{
	return direct_asin == 0 || direct_acos == 0 || direct_atan == 0 ||
		direct_atan2 == 0 || direct_asinf == 0 || direct_acosf == 0 ||
		direct_atanf == 0 || direct_atan2f == 0;
}
