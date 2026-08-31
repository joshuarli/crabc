/* Native Linux/x86-64 C++ declaration/linkage contract for sincos/sincosf. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fenv.h>
#include <float.h>
#include <math.h>

using double_sincos = void (*)(double, double *, double *);
using float_sincos = void (*)(float, float *, float *);

static double_sincos volatile direct_sincos = &(sincos);
static float_sincos volatile direct_sincosf = &(sincosf);

static_assert(sizeof(float) == 4 && alignof(float) == 4,
	"SysV binary32 storage");
static_assert(sizeof(double) == 8 && alignof(double) == 8,
	"SysV binary64 storage");
static_assert(FLT_RADIX == 2 && DBL_MANT_DIG == 53,
	"IEEE binary scalar contract");
/* The runner deliberately exercises ordinary SSE and x87 caller evaluation. */
static_assert(FLT_EVAL_METHOD == 0 || FLT_EVAL_METHOD == 2,
	"selected caller expression modes");

extern "C" int crabc_x86_64_math_sincos_header_probe(void)
{
	return direct_sincos == nullptr || direct_sincosf == nullptr;
}
