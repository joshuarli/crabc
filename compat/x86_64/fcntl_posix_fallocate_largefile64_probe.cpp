/* C++ Linux/x86-64 <fcntl.h> _LARGEFILE64_SOURCE posix_fallocate64 alias probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#define _LARGEFILE64_SOURCE 1
#ifdef _GNU_SOURCE
#error "posix_fallocate64 alias proof must not need _GNU_SOURCE"
#endif

#include <fcntl.h>

#ifndef posix_fallocate64
#error "_LARGEFILE64_SOURCE must expose the posix_fallocate64 alias"
#endif

using posix_fallocate64_largefile64_function = int (*)(int, off64_t, off64_t);
static_assert(sizeof(off_t) == 8 && sizeof(off64_t) == 8 &&
    static_cast<off_t>(-1) < 0 && static_cast<off64_t>(-1) < 0,
    "x86 C++ large-file POSIX signed 64-bit off_t/off64_t");
static_assert(
    __is_same(decltype(&posix_fallocate64),
        posix_fallocate64_largefile64_function),
    "x86 C++ posix_fallocate64 declaration");

int crabc_x86_64_fcntl_posix_fallocate_largefile64_probe_cpp()
{
    /* The macro must retain the base function's unmangled C reference. */
    return posix_fallocate64(-1, (off64_t)0, (off64_t)0);
}
