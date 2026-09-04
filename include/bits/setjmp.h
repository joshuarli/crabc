/* Linux/x86-64 machine context saved by setjmp and restored by longjmp. */
#if defined(__x86_64__)
#if !defined(__LP64__) || !defined(__BYTE_ORDER__) || \
	!defined(__ORDER_LITTLE_ENDIAN__) || \
	__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "crabc x86-64 setjmp requires little-endian LP64"
#endif

typedef unsigned long __jmp_buf[8];
#endif
