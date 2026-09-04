/* Native Linux/x86-64 C++ declaration/linkage contract for owned inverse trig. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <float.h>
#include <math.h>

using double_unary = double (*)(double);
using double_binary = double (*)(double, double);
using float_unary = float (*)(float);
using float_binary = float (*)(float, float);

static double_unary volatile direct_asin = &(asin);
static double_unary volatile direct_acos = &(acos);
static double_unary volatile direct_atan = &(atan);
static double_binary volatile direct_atan2 = &(atan2);
static float_unary volatile direct_asinf = &(asinf);
static float_unary volatile direct_acosf = &(acosf);
static float_unary volatile direct_atanf = &(atanf);
static float_binary volatile direct_atan2f = &(atan2f);

static_assert(sizeof(float) == 4 && alignof(float) == 4,
	"SysV binary32 storage");
static_assert(sizeof(double) == 8 && alignof(double) == 8,
	"SysV binary64 storage");
static_assert(FLT_RADIX == 2 && DBL_MANT_DIG == 53,
	"IEEE binary scalar contract");
static_assert(FLT_EVAL_METHOD == 0 || FLT_EVAL_METHOD == 2,
	"selected caller expression modes");

extern "C" int crabc_x86_64_owned_inverse_trig_header_probe(void)
{
	return direct_asin == nullptr || direct_acos == nullptr ||
		direct_atan == nullptr || direct_atan2 == nullptr ||
		direct_asinf == nullptr || direct_acosf == nullptr ||
		direct_atanf == nullptr || direct_atan2f == nullptr;
}
