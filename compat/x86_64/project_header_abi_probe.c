/*
 * Source-only Linux/x86-64 public-header ABI probe.
 *
 * Compile this fixture with the project include directory first and no link
 * step. It accepts only the explicitly staged x86-64 little-endian LP64
 * header declarations; it neither selects nor claims a crabc-libc artifact.
 * The pinned musl 1.2.6 x86 source build is the declaration/layout oracle.
 */

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#define __NEED_wchar_t
#define __NEED_float_t
#define __NEED_double_t
#include <bits/alltypes.h>
#include <fenv.h>
#include <float.h>

#define CRABC_TYPE_IS(expression, type) \
	_Generic((expression), type: 1, default: 0)

_Static_assert(__BYTE_ORDER == 1234, "x86-64 little-endian alltypes byte order");
_Static_assert(sizeof(wchar_t) == 4, "musl x86-64 wchar_t width");
_Static_assert((wchar_t)-1 < 0, "musl x86-64 wchar_t signedness");

#if defined(__FLT_EVAL_METHOD__) && __FLT_EVAL_METHOD__ == 2
_Static_assert(CRABC_TYPE_IS((float_t)0, long double),
	"x87 evaluation uses long-double float_t");
_Static_assert(CRABC_TYPE_IS((double_t)0, long double),
	"x87 evaluation uses long-double double_t");
#else
_Static_assert(CRABC_TYPE_IS((float_t)0, float),
	"SSE evaluation uses float float_t");
_Static_assert(CRABC_TYPE_IS((double_t)0, double),
	"SSE evaluation uses double double_t");
#endif

_Static_assert(sizeof(fexcept_t) == 2, "musl x86-64 fexcept_t width");
_Static_assert(_Alignof(fexcept_t) == 2, "musl x86-64 fexcept_t alignment");
_Static_assert(sizeof(fenv_t) == 32, "musl x86-64 fenv_t width");
_Static_assert(_Alignof(fenv_t) == 4, "musl x86-64 fenv_t alignment");
_Static_assert(__builtin_offsetof(fenv_t, __control_word) == 0,
	"x87 control word offset");
_Static_assert(__builtin_offsetof(fenv_t, __status_word) == 4,
	"x87 status word offset");
_Static_assert(__builtin_offsetof(fenv_t, __tags) == 8, "x87 tag word offset");
_Static_assert(__builtin_offsetof(fenv_t, __eip) == 12, "x87 instruction pointer offset");
_Static_assert(__builtin_offsetof(fenv_t, __cs_selector) == 16,
	"x87 code selector offset");
_Static_assert(__builtin_offsetof(fenv_t, __data_offset) == 20,
	"x87 data offset field");
_Static_assert(__builtin_offsetof(fenv_t, __data_selector) == 24,
	"x87 data selector offset");
_Static_assert(__builtin_offsetof(fenv_t, __mxcsr) == 28, "MXCSR offset");

#if FE_INVALID != 1 || __FE_DENORM != 2 || FE_DIVBYZERO != 4 || \
	FE_OVERFLOW != 8 || FE_UNDERFLOW != 16 || FE_INEXACT != 32 || \
	FE_ALL_EXCEPT != 63
#error "x86 fenv exception constants diverge from musl 1.2.6"
#endif

#if FE_TONEAREST != 0 || FE_DOWNWARD != 0x400 || FE_UPWARD != 0x800 || \
	FE_TOWARDZERO != 0xc00
#error "x86 fenv rounding constants diverge from musl 1.2.6"
#endif

#if FLT_RADIX != 2 || LDBL_MANT_DIG != 64 || LDBL_MIN_EXP != (-16381) || \
	LDBL_MAX_EXP != 16384 || LDBL_DIG != 18 || LDBL_MIN_10_EXP != (-4931) || \
	LDBL_MAX_10_EXP != 4932 || DECIMAL_DIG != 21 || LDBL_DECIMAL_DIG != 21
#error "x86 long-double float constants diverge from musl 1.2.6"
#endif

int crabc_x86_64_project_header_abi_probe(void)
{
	/* Compile-only: evaluating FLT_ROUNDS would require the future libc leaf. */
	return FLT_EVAL_METHOD + LDBL_MANT_DIG + FE_ALL_EXCEPT;
}
