/* Strict POSIX C++ Linux/x86-64 <fcntl.h> posix_fallocate declaration probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifdef _GNU_SOURCE
#error "strict POSIX posix_fallocate visibility must not need _GNU_SOURCE"
#endif
#ifdef _LARGEFILE64_SOURCE
#error "strict POSIX posix_fallocate probe must not select large-file aliases"
#endif

#include <fcntl.h>

#ifdef posix_fallocate64
#error "strict POSIX <fcntl.h> must not expose the posix_fallocate64 alias"
#endif

using posix_fallocate_strict_function = int (*)(int, off_t, off_t);
static_assert(sizeof(off_t) == 8 && static_cast<off_t>(-1) < 0,
    "x86 strict POSIX signed 64-bit off_t");
static_assert(
    __is_same(decltype(&posix_fallocate), posix_fallocate_strict_function),
    "x86 strict C++ posix_fallocate declaration");

int crabc_x86_64_fcntl_posix_fallocate_strict_probe_cpp()
{
    /* Keep an object-level reference so the runner can verify C linkage. */
    return posix_fallocate(-1, 0, 0);
}
