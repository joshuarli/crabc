/* C++17 companion to the permanent-stdin __fsetlocking stdio_ext.h probe.
 *
 * The used reference lets the runner prove the unmangled C spelling. This is
 * declaration-only evidence and does not establish a locking model.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_FSETLOCKING_STDIN_CXX17)
#error "the permanent-stdin fsetlocking C++17 profile must be selected"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
#endif

#include <stdio_ext.h>

using crabc_stdio_permanent_fsetlocking_stdin_signature = int (*)(FILE *, int);
static_assert(__is_same(decltype(&__fsetlocking),
    crabc_stdio_permanent_fsetlocking_stdin_signature),
    "__fsetlocking C++ declaration");
static_assert(FSETLOCKING_QUERY == 0, "FSETLOCKING_QUERY value");
static_assert(FSETLOCKING_INTERNAL == 1, "FSETLOCKING_INTERNAL value");
static_assert(FSETLOCKING_BYCALLER == 2, "FSETLOCKING_BYCALLER value");

__attribute__((used)) static crabc_stdio_permanent_fsetlocking_stdin_signature
    crabc_stdio_permanent_fsetlocking_stdin_reference = &__fsetlocking;

int crabc_x86_64_stdio_permanent_fsetlocking_stdin_header_abi_probe_cpp()
{
    return 0;
}
