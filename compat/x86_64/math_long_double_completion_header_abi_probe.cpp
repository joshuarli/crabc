/*
 * Native Linux/x86-64 C++17 GNU <math.h> declaration/linkage contract for
 * the selected binary80 fdiml/exp10l/pow10l closure.
 *
 * `fdiml` is a normal C99 declaration, while musl exposes `exp10l` and its
 * `pow10l` alias only through the GNU/BSD extension namespace.  Typed,
 * parenthesized addresses make both properties compile-time contracts and
 * retain the named C ABI references for the runner's ELF check.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#error "this probe requires the GNU <math.h> visibility profile"
#endif

#include <float.h>
#include <math.h>

using binary80_unary_signature = long double (*)(long double);
using binary80_binary_signature = long double (*)(long double, long double);

/*
 * Each initializer rejects a declaration with any different argument or
 * return type. Parentheses plus the runner's -fno-builtin keep these as
 * named C ABI references rather than compiler math substitutions.
 */
static binary80_binary_signature volatile direct_fdiml = &(fdiml);
static binary80_unary_signature volatile direct_exp10l = &(exp10l);
static binary80_unary_signature volatile direct_pow10l = &(pow10l);

static_assert(sizeof(long double) == 16 && alignof(long double) == 16,
	"SysV x86-64 binary80 storage");
static_assert(LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384,
	"SysV x86-64 binary80 format");
/* The runner deliberately compiles both ordinary SSE and x87 callers. */
static_assert(FLT_EVAL_METHOD == 0 || FLT_EVAL_METHOD == 2,
	"selected caller expression modes");

extern "C" int crabc_x86_64_math_long_double_completion_header_probe(void)
{
	return direct_fdiml == nullptr || direct_exp10l == nullptr ||
		direct_pow10l == nullptr;
}
