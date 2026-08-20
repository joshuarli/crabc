#ifndef _SETJMP_H
#define _SETJMP_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __aarch64__
typedef unsigned long jmp_buf[22];
typedef unsigned long sigjmp_buf[40];
#elif defined(__riscv)
typedef unsigned long jmp_buf[26];
typedef unsigned long sigjmp_buf[44];
#else
typedef unsigned long jmp_buf[8];
typedef unsigned long sigjmp_buf[10];
#endif

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 1))
#define __setjmp_attr __attribute__((__returns_twice__))
#else
#define __setjmp_attr
#endif

int setjmp(jmp_buf) __setjmp_attr;
_Noreturn void longjmp(jmp_buf, int);

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
int sigsetjmp(sigjmp_buf, int) __setjmp_attr;
_Noreturn void siglongjmp(sigjmp_buf, int);
#endif

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int _setjmp(jmp_buf) __setjmp_attr;
_Noreturn void _longjmp(jmp_buf, int);
#endif

#undef __setjmp_attr

#ifdef __cplusplus
}
#endif

#endif
