#ifndef _CRABC_BYTESWAP_H
#define _CRABC_BYTESWAP_H

#include <features.h>
#include <stdint.h>

static __inline uint16_t __bswap_16(uint16_t value) { return value << 8 | value >> 8; }
static __inline uint32_t __bswap_32(uint32_t value) {
    return value >> 24 | (value >> 8 & 0xff00) | (value << 8 & 0xff0000) | value << 24;
}
static __inline uint64_t __bswap_64(uint64_t value) {
    return (uint64_t)__bswap_32((uint32_t)value) << 32 | __bswap_32((uint32_t)(value >> 32));
}

#define bswap_16(value) __bswap_16(value)
#define bswap_32(value) __bswap_32(value)
#define bswap_64(value) __bswap_64(value)

#endif
