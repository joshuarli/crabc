#if defined(__x86_64__)
/* Linux/x86-64 machine context saved by setjmp and restored by longjmp. */
#if defined(__x86_64__)
#if !defined(__LP64__) || !defined(__BYTE_ORDER__) || \
	!defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "crabc x86-64 setjmp requires little-endian LP64"
#endif

typedef unsigned long __jmp_buf[8];
#endif
#elif defined(__aarch64__)
/* musl 1.2.6 aarch64/bits/setjmp.h, MIT licensed. */
typedef unsigned long __jmp_buf[22];

#endif
