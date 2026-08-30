/* Freestanding C++17 companion for libc_uio_cxx_linkage_probe.c.
 *
 * No C++ standard headers, constructors, exceptions, RTTI, allocation, or
 * TLS are admitted.  The function-pointer calls ensure the C++ declarations
 * in <sys/uio.h> retain their unmangled C names all the way into the selected
 * static crabc-libc archive.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <sys/uio.h>

using vector_io_function = ssize_t (*)(int, const struct iovec *, int);
using positioned_vector_io_function = ssize_t (*)(int, const struct iovec *,
    int, off_t);

static_assert(sizeof(struct iovec) == 16 && alignof(struct iovec) == 8,
    "C++ x86 iovec layout");
static_assert(__is_same(decltype(&readv), vector_io_function),
    "readv C linkage declaration");
static_assert(__is_same(decltype(&writev), vector_io_function),
    "writev C linkage declaration");
static_assert(__is_same(decltype(&preadv), positioned_vector_io_function),
    "preadv C linkage declaration");
static_assert(__is_same(decltype(&pwritev), positioned_vector_io_function),
    "pwritev C linkage declaration");

extern "C" int crabc_x86_64_uio_cxx_linkage_probe(int write_descriptor,
    int read_descriptor)
{
    char first[] = "C+";
    char second[] = "+";
    char received[4] = { 0, 0, 0, 0 };
    struct iovec outgoing[2] = {
        { first, sizeof(first) - 1 },
        { second, sizeof(second) - 1 },
    };
    struct iovec incoming = { received, sizeof(received) - 1 };
    vector_io_function write_vector = &writev;
    vector_io_function read_vector = &readv;
    positioned_vector_io_function read_positioned = &preadv;
    positioned_vector_io_function write_positioned = &pwritev;

    if (write_vector(write_descriptor, outgoing, 2) != 3)
        return 10;
    if (read_vector(read_descriptor, &incoming, 1) != 3 ||
        received[0] != 'C' || received[1] != '+' || received[2] != '+')
        return 11;

    errno = 0;
    if (read_positioned(read_descriptor, &incoming, 1, 0) != -1 ||
        errno != ESPIPE)
        return 12;
    errno = 0;
    if (write_positioned(write_descriptor, outgoing, 1, 0) != -1 ||
        errno != ESPIPE)
        return 13;
    return 0;
}
