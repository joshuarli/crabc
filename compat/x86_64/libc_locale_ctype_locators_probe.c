/* Fixed-C-locale musl ctype-locator ABI fixture shared by musl/crabc. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native little-endian Linux/x86-64 LP64"
#endif

#include <ctype.h>
#include <stdint.h>
#include <unistd.h>

/*
 * These musl glibc-compatibility symbols are intentionally ABI-only: neither
 * musl nor crabc declares them in the installed ctype.h.  A consumer that
 * needs this compatibility surface supplies the declaration itself.
 */
extern const unsigned short **__ctype_b_loc(void);
extern const int32_t **__ctype_tolower_loc(void);
extern const int32_t **__ctype_toupper_loc(void);

static uint64_t mix_byte(uint64_t hash, unsigned char value)
{
    return (hash ^ value) * UINT64_C(1099511628211);
}

static uint64_t mix_u16(uint64_t hash, uint16_t value)
{
    hash = mix_byte(hash, (unsigned char)value);
    return mix_byte(hash, (unsigned char)(value >> 8));
}

static uint64_t mix_i32(uint64_t hash, int32_t value)
{
    uint32_t bits = (uint32_t)value;
    unsigned shift;

    for (shift = 0; shift != 32; shift += 8)
        hash = mix_byte(hash, (unsigned char)(bits >> shift));
    return hash;
}

static int check_locator_shape(const unsigned short **class_locator,
    const int32_t **lower_locator, const int32_t **upper_locator)
{
    const unsigned short *classes;
    const int32_t *lower;
    const int32_t *upper;

    if (!class_locator || !lower_locator || !upper_locator ||
        class_locator != __ctype_b_loc() ||
        lower_locator != __ctype_tolower_loc() ||
        upper_locator != __ctype_toupper_loc())
        return 1;

    classes = *class_locator;
    lower = *lower_locator;
    upper = *upper_locator;
    if (!classes || !lower || !upper || classes != *__ctype_b_loc() ||
        lower != *__ctype_tolower_loc() || upper != *__ctype_toupper_loc())
        return 2;

    /* musl's 16-bit class ABI is network-byte-order data on this target. */
    if (classes[-128] != UINT16_C(0) || classes[-1] != UINT16_C(0) ||
        classes[0] != UINT16_C(0x0002) || classes['\t'] != UINT16_C(0x2003) ||
        classes['\n'] != UINT16_C(0x2002) || classes[' '] != UINT16_C(0x6001) ||
        classes['!'] != UINT16_C(0xc004) || classes['0'] != UINT16_C(0xd808) ||
        classes['A'] != UINT16_C(0xd508) || classes['G'] != UINT16_C(0xc508) ||
        classes['a'] != UINT16_C(0xd608) || classes['g'] != UINT16_C(0xc608) ||
        classes[0x7f] != UINT16_C(0x0002) || classes[0x80] != UINT16_C(0) ||
        classes[255] != UINT16_C(0))
        return 3;

    if (lower[-128] != 0 || lower[-1] != 0 || lower[0] != 0 ||
        lower['A'] != 'a' || lower['Z'] != 'z' || lower['a'] != 'a' ||
        lower['!'] != '!' || lower[0x7f] != 0x7f || lower[0x80] != 0 ||
        lower[255] != 0 || upper[-128] != 0 || upper[-1] != 0 ||
        upper[0] != 0 || upper['a'] != 'A' || upper['z'] != 'Z' ||
        upper['A'] != 'A' || upper['!'] != '!' || upper[0x7f] != 0x7f ||
        upper[0x80] != 0 || upper[255] != 0)
        return 4;

    return 0;
}

static long raw_write_stdout(const void *bytes, long count)
{
    long result = 1;

    __asm__ volatile (
        "syscall"
        : "+a"(result)
        : "D"(1L), "S"(bytes), "d"(count)
        : "rcx", "r11", "memory"
    );
    return result;
}

static int emit_fingerprint(uint64_t fingerprint)
{
    unsigned char bytes[8];
    unsigned index;

    for (index = 0; index != sizeof(bytes); ++index)
        bytes[index] = (unsigned char)(fingerprint >> (index * 8));
    return raw_write_stdout(bytes, (long)sizeof(bytes)) == (long)sizeof(bytes)
        ? 0 : 1;
}

int crabc_x86_64_locale_ctype_locators_probe(void)
{
    const unsigned short **class_locator = __ctype_b_loc();
    const int32_t **lower_locator = __ctype_tolower_loc();
    const int32_t **upper_locator = __ctype_toupper_loc();
    const unsigned short *classes;
    const int32_t *lower;
    const int32_t *upper;
    uint64_t fingerprint = UINT64_C(1469598103934665603);
    int character;
    int status;

    status = check_locator_shape(class_locator, lower_locator, upper_locator);
    if (status != 0)
        return status;
    classes = *class_locator;
    lower = *lower_locator;
    upper = *upper_locator;

    for (character = -128; character != 256; ++character) {
        fingerprint = mix_u16(fingerprint, classes[character]);
        fingerprint = mix_i32(fingerprint, lower[character]);
        fingerprint = mix_i32(fingerprint, upper[character]);
    }
    return emit_fingerprint(fingerprint) == 0 ? 0 : 10;
}

#ifndef CRABC_LOCALE_CTYPE_LOCATORS_FREESTANDING
int main(void)
{
    return crabc_x86_64_locale_ctype_locators_probe();
}
#endif
