/* Static Linux/x86-64 bcopy/bzero C ABI and behavior fixture.
 *
 * The selected legacy adapters retain only bcopy's overlap-safe byte copy and
 * bzero's caller-owned byte clearing. They neither allocate nor publish errno,
 * TLS, locale, process, or runtime state.
 */

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <string.h>
#include <strings.h>

typedef void (*bcopy_signature)(const void *, void *, size_t);
typedef void (*bzero_signature)(void *, size_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&bcopy), bcopy_signature),
    "bcopy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&bzero), bzero_signature),
    "bzero declaration");

enum { CRABC_LEGACY_MEMORY_BYTES = 96 };

static void fill_bytes(unsigned char *bytes, unsigned seed)
{
    size_t index;

    for (index = 0; index < CRABC_LEGACY_MEMORY_BYTES; ++index)
        bytes[index] = (unsigned char)(seed + index * 37U);
}

static void copy_bytes(unsigned char *destination, const unsigned char *source)
{
    size_t index;

    for (index = 0; index < CRABC_LEGACY_MEMORY_BYTES; ++index)
        destination[index] = source[index];
}

static int check_bcopy_overlap(void)
{
    unsigned char bytes[CRABC_LEGACY_MEMORY_BYTES];
    unsigned char before[CRABC_LEGACY_MEMORY_BYTES];
    size_t length;
    size_t source;
    size_t destination;
    size_t index;

    for (length = 0; length <= 48; ++length) {
        for (source = 0; source + length <= 64; source += 5) {
            for (destination = 0; destination + length <= 64; destination += 3) {
                fill_bytes(bytes, (unsigned)(length + source * 3 + destination * 5));
                copy_bytes(before, bytes);
                bcopy(bytes + source, bytes + destination, length);
                for (index = 0; index < CRABC_LEGACY_MEMORY_BYTES; ++index) {
                    unsigned char expected = before[index];

                    if (index >= destination && index - destination < length)
                        expected = before[source + index - destination];
                    if (bytes[index] != expected)
                        return 1;
                }
            }
        }
    }
    return 0;
}

static int check_bzero_ranges(void)
{
    unsigned char bytes[CRABC_LEGACY_MEMORY_BYTES];
    size_t offset;
    size_t length;
    size_t index;

    for (length = 0; length <= 64; ++length) {
        for (offset = 0; offset + length <= CRABC_LEGACY_MEMORY_BYTES; offset += 7) {
            fill_bytes(bytes, (unsigned)(length * 11 + offset));
            bzero(bytes + offset, length);
            for (index = 0; index < CRABC_LEGACY_MEMORY_BYTES; ++index) {
                unsigned char expected = (unsigned char)(length * 11 + offset + index * 37U);

                if (index >= offset && index - offset < length)
                    expected = 0;
                if (bytes[index] != expected)
                    return 2;
            }
        }
    }
    return 0;
}

int crabc_x86_64_legacy_memory_probe(void)
{
    int result;

    result = check_bcopy_overlap();
    if (result != 0)
        return result;
    return check_bzero_ranges();
}

#ifndef CRABC_LEGACY_MEMORY_FREESTANDING
int main(void)
{
    return crabc_x86_64_legacy_memory_probe();
}
#endif
