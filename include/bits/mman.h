#ifndef _BITS_MMAN_H
#define _BITS_MMAN_H

/* Linux/x86-64's architecture-specific mapping hint. */
#if defined(__x86_64__)
#if !defined(__LP64__) || !defined(__BYTE_ORDER__) || \
    !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "crabc x86-64 sys/mman declarations require little-endian LP64"
#endif
#define MAP_32BIT 0x40
#endif

#endif
