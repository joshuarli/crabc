#if defined(__x86_64__)
#if defined(__x86_64__)
/* Linux/x86-64's architecture-specific mapping hint. */
#define MAP_32BIT 0x40
#endif
#elif defined(__aarch64__)
/* musl 1.2.6 aarch64/bits/mman.h, MIT licensed. */
#define PROT_BTI 0x10
#define PROT_MTE 0x20

#endif
