/*
 * Source-only Linux/x86-64 C-runtime primitive-composition fixture.
 *
 * The runner executes this unchanged against pinned musl 1.2.6 and an
 * isolated crabc object. It proves only that the selected fixed-six-word raw
 * syscall bridge publishes errors in the same initial-TLS errno slot while
 * the already-proved memory and fenv symbols coexist in one native object.
 * It neither links crabc-libc nor admits broader C/POSIX behavior.
 */

#define _GNU_SOURCE 1

#include <errno.h>
#include <fenv.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#if defined(CRABC_FOUNDATION_ORACLE)
/* Only the pinned-musl oracle wrapper calls public variadic syscall(2).
 * The candidate branch below uses the private fixed-arity bridge instead. */
#include <unistd.h>
#endif

#if !defined(__x86_64__) || !defined(__LP64__) || \
	!defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(long) == 8, "x86 C long width");
_Static_assert(sizeof(void *) == 8, "x86 C pointer width");
_Static_assert(SYS_getpid == 39, "x86 getpid syscall number");
_Static_assert(SYS_close == 3, "x86 close syscall number");

/* This is deliberately not public C syscall(2): the isolated foundation
 * requires all six raw words explicitly instead of reading absent varargs. */
#if defined(CRABC_FOUNDATION_ORACLE)
static long crabc_x86_64_foundation_syscall6(long number, long a, long b,
	long c, long d, long e, long f)
{
	return syscall(number, a, b, c, d, e, f);
}
#else
extern long crabc_x86_64_foundation_syscall6(long, long, long, long, long,
	long, long);
#endif

static int test_syscall_errno(void)
{
	int *const slot = __errno_location();
	long result;

	if (slot == 0 || errno != 0)
		return 10;

	/* Linux ignores the unused raw words for getpid, but this source-only
	 * bridge receives every word as an ordinary fixed C ABI argument. */
	result = crabc_x86_64_foundation_syscall6(
		SYS_getpid, 0L, 0L, 0L, 0L, 0L, 0L);
	if (result <= 0 || errno != 0 || __errno_location() != slot)
		return 11;

	errno = 0;
	result = crabc_x86_64_foundation_syscall6(
		SYS_close, -1L, 0L, 0L, 0L, 0L, 0L);
	if (result != -1 || errno != EBADF || __errno_location() != slot)
		return 12;

	return 0;
}

static int test_memory(void)
{
	unsigned char bytes[12];
	unsigned char source[4] = { 1, 2, 3, 4 };
	void *(*const copy)(void *, const void *, size_t) = memcpy;
	void *(*const move)(void *, const void *, size_t) = memmove;
	void *(*const fill)(void *, int, size_t) = memset;

	if (fill(bytes, 0, sizeof(bytes)) != bytes)
		return 20;
	if (copy(bytes + 2, source, sizeof(source)) != bytes + 2)
		return 21;
	if (bytes[2] != 1 || bytes[3] != 2 || bytes[4] != 3 || bytes[5] != 4)
		return 22;
	if (move(bytes + 3, bytes + 2, sizeof(source)) != bytes + 3)
		return 23;
	if (bytes[3] != 1 || bytes[4] != 2 || bytes[5] != 3 || bytes[6] != 4)
		return 24;
	return 0;
}

static int test_fenv(void)
{
	fenv_t saved;

	if (fegetenv(&saved) != 0)
		return 30;
	if (feclearexcept(FE_ALL_EXCEPT) != 0)
		return 31;
	if (feraiseexcept(FE_INVALID) != 0)
		return 32;
	if ((fetestexcept(FE_ALL_EXCEPT) & FE_INVALID) != FE_INVALID)
		return 33;
	if (fesetenv(&saved) != 0)
		return 34;
	return 0;
}

int main(void)
{
	int result;

	if ((result = test_syscall_errno()) != 0)
		return result;
	if ((result = test_memory()) != 0)
		return result;
	if ((result = test_fenv()) != 0)
		return result;
	return 0;
}
