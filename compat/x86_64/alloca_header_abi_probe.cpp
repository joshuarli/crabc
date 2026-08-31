/* C++ companion for the Linux/x86-64 <alloca.h> builtin-macro probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <alloca.h>

#ifndef alloca
#error "musl-compatible alloca must be a compiler-builtin macro"
#endif

static_assert(sizeof(size_t) == 8, "x86-64 size_t width");
static_assert(__is_same(decltype(alloca(static_cast<size_t>(1))), void *),
    "alloca builtin result type");

int crabc_x86_64_alloca_header_abi_probe_cpp()
{
    void *storage = alloca(static_cast<size_t>(1));

    return storage == nullptr;
}
