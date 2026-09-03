/* Source-only Linux/x86-64 C stddef declaration and layout probe. */

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

#define CRABC_TYPE_IS(expression, type) \
    _Generic((expression), type: 1, default: 0)

struct crabc_stddef_layout {
    char tag;
    long value;
};

static void *const crabc_stddef_null_pointer = NULL;

_Static_assert(CRABC_TYPE_IS((size_t)0, unsigned long),
    "musl x86-64 size_t is unsigned long");
_Static_assert(CRABC_TYPE_IS((ptrdiff_t)0, long),
    "musl x86-64 ptrdiff_t is signed long");
_Static_assert(CRABC_TYPE_IS((wchar_t)0, int),
    "musl x86-64 C wchar_t is signed int");
_Static_assert(sizeof(size_t) == 8 && _Alignof(size_t) == 8 &&
    sizeof(ptrdiff_t) == 8 && _Alignof(ptrdiff_t) == 8 &&
    sizeof(wchar_t) == 4 && _Alignof(wchar_t) == 4,
    "musl x86-64 fundamental type layouts");
_Static_assert(sizeof(max_align_t) == 32 && _Alignof(max_align_t) == 16,
    "musl x86-64 max_align_t layout");
_Static_assert(offsetof(struct crabc_stddef_layout, value) == 8,
    "musl offsetof builtin spelling");

int crabc_x86_64_stddef_header_abi_probe(void)
{
    return crabc_stddef_null_pointer == NULL ? 0 : 1;
}
