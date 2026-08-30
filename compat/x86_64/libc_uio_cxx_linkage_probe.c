/* Static x86-64 C/C++ <sys/uio.h> archive-linkage fixture.
 *
 * This C entry calls one separately compiled, freestanding C++17 companion.
 * It closes only the selected C++ declaration-to-static-archive seam for
 * readv, writev, preadv, and pwritev after the existing header-profile and
 * C-runtime artifacts have independently established their boundaries.  It
 * is not a C++ runtime, a general C ABI, or header-family completion.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

_Static_assert(sizeof(struct iovec) == 16 && _Alignof(struct iovec) == 8,
    "x86 iovec layout");

/* The companion has C linkage and needs no C++ runtime startup. */
int crabc_x86_64_uio_cxx_linkage_probe(int write_descriptor,
    int read_descriptor);

int crabc_x86_64_uio_cxx_linkage_entry(void)
{
    int pair[2] = { -1, -1 };
    int status;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        return 1;
    status = crabc_x86_64_uio_cxx_linkage_probe(pair[0], pair[1]);
    if (close(pair[1]) != 0 && status == 0)
        status = 2;
    if (close(pair[0]) != 0 && status == 0)
        status = 3;
    return status;
}

#ifndef CRABC_UIO_CXX_LINKAGE_FREESTANDING
int main(void)
{
    return crabc_x86_64_uio_cxx_linkage_entry();
}
#endif
