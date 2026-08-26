#ifndef _SETJMP_H
#define _SETJMP_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__x86_64__)
/*
 * SysV x86-64 saves six callee-saved GPRs, post-return RSP, and RIP. The
 * remaining public record is musl's signal-mask continuation state, not
 * spare machine words; use the named record so callers cannot mistake this
 * 200-byte ABI for the AArch64 context below.
 */
#include <features.h>
#include <bits/setjmp.h>

typedef struct __jmp_buf_tag {
	__jmp_buf __jb;
	unsigned long __fl;
	unsigned long __ss[128 / sizeof(long)];
} jmp_buf[1];

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
typedef jmp_buf sigjmp_buf;
#endif

#else
typedef unsigned long jmp_buf[22];
typedef unsigned long sigjmp_buf[40];
#endif

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 1))
#define __setjmp_attr __attribute__((__returns_twice__))
#else
#define __setjmp_attr
#endif

int setjmp(jmp_buf) __setjmp_attr;
_Noreturn void longjmp(jmp_buf, int);

#if !defined(__x86_64__) && (defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE))
int sigsetjmp(sigjmp_buf, int) __setjmp_attr;
_Noreturn void siglongjmp(sigjmp_buf, int);
#elif defined(__x86_64__) && (defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE))
int sigsetjmp(sigjmp_buf, int) __setjmp_attr;
_Noreturn void siglongjmp(sigjmp_buf, int);
#endif

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int _setjmp(jmp_buf) __setjmp_attr;
_Noreturn void _longjmp(jmp_buf, int);
#endif

#if defined(__x86_64__)
#define setjmp setjmp
#endif

#undef __setjmp_attr

#ifdef __cplusplus
}
#endif

#endif
