/* Static Linux/x86-64 alloca compiler-builtin behavior fixture.
 *
 * The returned storage is used only in its allocating function.  This covers
 * positive dynamic request sizes and a nested active frame; it intentionally
 * does not define alloca(0), stack exhaustion, VLA, unwind, or escaping
 * pointer behavior.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <alloca.h>

#ifndef alloca
#error "musl-compatible alloca must be a compiler-builtin macro"
#endif

_Static_assert(sizeof(size_t) == 8, "x86-64 size_t width");

static unsigned char alloca_pattern(size_t index, unsigned char seed)
{
    return (unsigned char)((index * (size_t)29U + (size_t)seed) ^ (index >> 3));
}

/* Keep the request dynamic in the emitted static candidate, rather than
 * letting a constant-sized local array stand in for the builtin boundary. */
__attribute__((noinline))
static int crabc_x86_64_alloca_case(size_t size, unsigned char seed)
{
    volatile unsigned char *storage;
    size_t index;

    storage = (volatile unsigned char *)alloca(size);
    if (storage == 0)
        return 1;
    if (((unsigned long)storage & 15UL) != 0)
        return 2;

    for (index = 0; index < size; ++index)
        storage[index] = alloca_pattern(index, seed);
    for (index = 0; index < size; ++index) {
        if (storage[index] != alloca_pattern(index, seed))
            return 3;
    }

    return 0;
}

__attribute__((noinline))
static int crabc_x86_64_alloca_nested_case(void)
{
    volatile unsigned char *outer;
    size_t index;
    int status;

    outer = (volatile unsigned char *)alloca((size_t)257);
    if (outer == 0)
        return 1;
    for (index = 0; index < (size_t)257; ++index)
        outer[index] = alloca_pattern(index, (unsigned char)0x6dU);

    status = crabc_x86_64_alloca_case((size_t)513, (unsigned char)0xb4U);
    if (status != 0)
        return 10 + status;
    for (index = 0; index < (size_t)257; ++index) {
        if (outer[index] != alloca_pattern(index, (unsigned char)0x6dU))
            return 20;
    }

    return 0;
}

int crabc_x86_64_alloca_probe(void)
{
    static const size_t sizes[] = {
        (size_t)1, (size_t)2, (size_t)15, (size_t)16, (size_t)17,
        (size_t)31, (size_t)32, (size_t)33, (size_t)127, (size_t)255,
        (size_t)256, (size_t)257, (size_t)1024,
    };
    size_t index;
    int status;

    for (index = 0; index < sizeof(sizes) / sizeof(sizes[0]); ++index) {
        status = crabc_x86_64_alloca_case(
            sizes[index], (unsigned char)(0x11U + (unsigned char)index));
        if (status != 0)
            return 40 + status;
    }

    status = crabc_x86_64_alloca_nested_case();
    return status == 0 ? 0 : 80 + status;
}

#ifndef CRABC_ALLOCA_FREESTANDING
int main(void)
{
    return crabc_x86_64_alloca_probe();
}
#endif
