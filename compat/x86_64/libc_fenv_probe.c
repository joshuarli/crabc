/*
 * Source-only Linux/x86-64 C fenv ABI fixture.
 *
 * The runner builds this once with pinned musl 1.2.6, then with project
 * headers and the isolated crabc x86 fenv object. It exercises the exact
 * x87/MXCSR fenv surface only; neither result selects crabc-libc.
 */

#include <fenv.h>
#include <stddef.h>
#include <stdint.h>

/* This internal C99 helper backs the public `FLT_ROUNDS` macro on musl. */
extern int __flt_rounds(void);

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(fexcept_t) == 2, "x86 fexcept_t width");
_Static_assert(sizeof(fenv_t) == 32, "x86 fenv_t width");
_Static_assert(_Alignof(fenv_t) == 4, "x86 fenv_t alignment");
_Static_assert(offsetof(fenv_t, __status_word) == 4, "x87 status-word offset");
_Static_assert(offsetof(fenv_t, __mxcsr) == 28, "x86 MXCSR offset");

static int test_fenv(void)
{
	fenv_t original;
	fenv_t held;
	fexcept_t flags;
	int prior_round;

	if (fegetenv(&original) != 0)
		return 10;
	if (fesetenv(FE_DFL_ENV) != 0)
		return 11;
	if (fegetround() != FE_TONEAREST || __flt_rounds() != 1)
		return 12;
	if (fetestexcept(FE_ALL_EXCEPT) != 0)
		return 13;

	if (fesetround(FE_DOWNWARD) != 0 || fegetround() != FE_DOWNWARD ||
		__flt_rounds() != 3)
		return 14;
	prior_round = fegetround();
	if (fesetround(0x200) != -1 || fegetround() != prior_round)
		return 15;

	if (feraiseexcept(FE_INVALID | __FE_DENORM | FE_INEXACT) != 0)
		return 16;
	if (fetestexcept(FE_ALL_EXCEPT) !=
		(FE_INVALID | __FE_DENORM | FE_INEXACT))
		return 17;
	if (fegetexceptflag(&flags, FE_ALL_EXCEPT) != 0 ||
		flags != (FE_INVALID | __FE_DENORM | FE_INEXACT))
		return 18;

	flags = FE_DIVBYZERO | FE_OVERFLOW;
	if (fesetexceptflag(&flags, FE_ALL_EXCEPT) != 0 ||
		fetestexcept(FE_ALL_EXCEPT) != flags)
		return 19;

	if (feholdexcept(&held) != 0 || fegetround() != FE_DOWNWARD ||
		fetestexcept(FE_ALL_EXCEPT) != 0)
		return 20;
	if (feraiseexcept(FE_INEXACT) != 0 ||
		feupdateenv(&held) != 0 ||
		fetestexcept(FE_ALL_EXCEPT) !=
			(FE_DIVBYZERO | FE_OVERFLOW | FE_INEXACT))
		return 21;

	if (fesetenv(FE_DFL_ENV) != 0 || fegetround() != FE_TONEAREST ||
		__flt_rounds() != 1 || fetestexcept(FE_ALL_EXCEPT) != 0)
		return 22;
	if (fesetenv(&original) != 0)
		return 23;
	return 0;
}

int main(void)
{
	return test_fenv();
}
