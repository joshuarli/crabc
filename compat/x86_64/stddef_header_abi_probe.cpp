/* Source-only Linux/x86-64 C++17 stddef declaration and layout probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>

#ifndef _STDDEF_H
#error "musl stddef guard is missing"
#endif

#if defined(_CRABC_STDDEF_H)
#error "x86 stddef must not expose the historical AArch64 guard"
#endif

#if !defined(__NEED_ptrdiff_t) || !defined(__NEED_size_t) || \
    !defined(__NEED_wchar_t) || !defined(__NEED_max_align_t)
#error "musl stddef type requests are missing"
#endif

struct crabc_stddef_layout {
    char tag;
    long value;
};

static void *const crabc_stddef_null_pointer = NULL;

static_assert(__is_same(size_t, unsigned long),
    "musl x86-64 size_t is unsigned long");
static_assert(__is_same(ptrdiff_t, long),
    "musl x86-64 ptrdiff_t is signed long");
static_assert(sizeof(size_t) == 8 && alignof(size_t) == 8 &&
    sizeof(ptrdiff_t) == 8 && alignof(ptrdiff_t) == 8 &&
    sizeof(wchar_t) == 4 && alignof(wchar_t) == 4,
    "musl x86-64 C++ fundamental type layouts");
static_assert(sizeof(max_align_t) == 32 && alignof(max_align_t) == 16,
    "musl x86-64 C++ max_align_t layout");
static_assert(__is_same(decltype(NULL), decltype(nullptr)),
    "musl C++17 NULL is nullptr");
static_assert(offsetof(crabc_stddef_layout, value) == 8,
    "musl offsetof builtin spelling");

int crabc_x86_64_stddef_header_abi_probe_cpp()
{
    return crabc_stddef_null_pointer == nullptr ? 0 : 1;
}
