/* C++ source-only companion for the staged x86-64 <sys/mman.h> ABI. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/mman.h>

using mmap_type = void *(*)(void *, size_t, int, int, int, off_t);
using mremap_type = void *(*)(void *, size_t, size_t, int, ...);

static_assert(__is_same(decltype(&mmap), mmap_type),
    "C++ mmap declaration");
static_assert(__is_same(decltype(&mremap), mremap_type),
    "C++ mremap declaration");
static_assert(__is_same(decltype(&munmap), int (*)(void *, size_t)),
    "C++ munmap declaration");
static_assert(__is_same(decltype(&mprotect), int (*)(void *, size_t, int)),
    "C++ mprotect declaration");
static_assert(MAP_32BIT == 0x40 && MAP_FIXED_NOREPLACE == 0x100000,
    "C++ x86 mapping values");
static_assert(MAP_HUGE_16GB == (34U << 26), "C++ huge-page encoding");

int crabc_x86_64_mman_header_abi_probe_cpp()
{
    return MAP_32BIT + MAP_FIXED_NOREPLACE;
}
