/*
 * Native x86-64 C data-model and x87 fenv probe.
 *
 * This fixture deliberately includes the toolchain's native headers rather
 * than crabc's AArch64 public header tree.  It captures the compiler-level
 * SysV LP64/x87 baseline that the future x86 public-header split must meet.
 * It is not a crabc-libc build. `header-abi-reference` compiles it only with
 * the pinned musl-1.2.6 oracle; it is a reference baseline, not candidate
 * crabc header acceptance or public x86 C support.
 */

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native SysV x86-64 LP64"
#endif

#include <complex.h>
#include <fenv.h>
#include <float.h>
#include <stddef.h>
#include <stdio.h>

_Static_assert(sizeof(void *) == 8, "x86-64 pointer width");
_Static_assert(sizeof(long) == 8, "x86-64 long width");
_Static_assert(sizeof(size_t) == 8, "x86-64 size_t width");
_Static_assert(sizeof(ptrdiff_t) == 8, "x86-64 ptrdiff_t width");

_Static_assert(sizeof(long double) == 16, "SysV x86-64 long double storage");
_Static_assert(_Alignof(long double) == 16, "SysV x86-64 long double alignment");
_Static_assert(__LDBL_MANT_DIG__ == 64, "x87 extended precision mantissa");
_Static_assert(__LDBL_MAX_EXP__ == 16384, "x87 extended precision exponent");
_Static_assert(sizeof(long double _Complex) == 32, "SysV x86-64 complex long double");
_Static_assert(_Alignof(long double _Complex) == 16, "complex long double alignment");

_Static_assert(sizeof(fexcept_t) == 2, "musl x86-64 fexcept_t");
_Static_assert(_Alignof(fexcept_t) == 2, "musl x86-64 fexcept_t alignment");
_Static_assert(sizeof(fenv_t) == 32, "musl x86-64 fenv_t");
_Static_assert(_Alignof(fenv_t) == 4, "musl x86-64 fenv_t alignment");
_Static_assert(offsetof(fenv_t, __control_word) == 0, "x87 control-word offset");
_Static_assert(offsetof(fenv_t, __status_word) == 4, "x87 status-word offset");
_Static_assert(offsetof(fenv_t, __tags) == 8, "x87 tag-word offset");
_Static_assert(offsetof(fenv_t, __eip) == 12, "x87 instruction-pointer offset");
_Static_assert(offsetof(fenv_t, __cs_selector) == 16, "x87 code-selector offset");
_Static_assert(offsetof(fenv_t, __data_offset) == 20, "x87 data-offset field");
_Static_assert(offsetof(fenv_t, __data_selector) == 24, "x87 data-selector offset");
_Static_assert(offsetof(fenv_t, __mxcsr) == 28, "MXCSR offset");

_Static_assert(FE_INVALID == 1, "x86 FE_INVALID");
_Static_assert(FE_DIVBYZERO == 4, "x86 FE_DIVBYZERO");
_Static_assert(FE_OVERFLOW == 8, "x86 FE_OVERFLOW");
_Static_assert(FE_UNDERFLOW == 16, "x86 FE_UNDERFLOW");
_Static_assert(FE_INEXACT == 32, "x86 FE_INEXACT");
_Static_assert(FE_ALL_EXCEPT == 63, "x86 FE_ALL_EXCEPT");
_Static_assert(FE_TONEAREST == 0, "x86 FE_TONEAREST");
_Static_assert(FE_DOWNWARD == 0x400, "x86 FE_DOWNWARD");
_Static_assert(FE_UPWARD == 0x800, "x86 FE_UPWARD");
_Static_assert(FE_TOWARDZERO == 0xc00, "x86 FE_TOWARDZERO");
_Static_assert(LDBL_MANT_DIG == 64, "musl x86-64 LDBL_MANT_DIG");
_Static_assert(LDBL_MAX_EXP == 16384, "musl x86-64 LDBL_MAX_EXP");
_Static_assert(LDBL_DIG == 18, "musl x86-64 LDBL_DIG");
_Static_assert(DECIMAL_DIG == 21, "musl x86-64 DECIMAL_DIG");

__attribute__((noinline))
static long double long_double_round_trip(long double value)
{
    return value;
}

__attribute__((noinline))
static long double _Complex long_double_complex_round_trip(long double _Complex value)
{
    return value;
}

int main(void)
{
    volatile long double input = 1.0L / 3.0L;
    long double output = long_double_round_trip(input);
    long double _Complex complex_output = long_double_complex_round_trip(input + input * I);

    if (output != input || creall(complex_output) != input || cimagl(complex_output) != input)
        return 1;

    printf("ptr=%zu long=%zu size=%zu ptrdiff=%zu ld=%zu/%zu ldc=%zu/%zu ",
        sizeof(void *), sizeof(long), sizeof(size_t), sizeof(ptrdiff_t),
        sizeof(long double), _Alignof(long double),
        sizeof(long double _Complex), _Alignof(long double _Complex));
    printf("fexcept=%zu/%zu fenv=%zu/%zu mxcsr=%zu flags=%d,%d,%d,%d,%d,%d rounds=%d,%d,%d,%d ",
        sizeof(fexcept_t), _Alignof(fexcept_t), sizeof(fenv_t), _Alignof(fenv_t),
        offsetof(fenv_t, __mxcsr), FE_INVALID, FE_DIVBYZERO, FE_OVERFLOW,
        FE_UNDERFLOW, FE_INEXACT, FE_ALL_EXCEPT, FE_TONEAREST, FE_DOWNWARD,
        FE_UPWARD, FE_TOWARDZERO);
    printf("ldbl=%d,%d,%d,%d\n", LDBL_MANT_DIG, LDBL_MAX_EXP, LDBL_DIG, DECIMAL_DIG);
    return 0;
}
