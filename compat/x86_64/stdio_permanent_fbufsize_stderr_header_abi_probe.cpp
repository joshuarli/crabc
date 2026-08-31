/* C++17 companion to the permanent-stderr __fbufsize stdio_ext.h probe.
 *
 * The used reference lets the runner prove the unmangled C spelling. This is
 * declaration-only evidence and does not widen the selected stream model.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_FBUFSIZE_STDERR_CXX17)
#error "the permanent-stderr fbufsize C++17 profile must be selected"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
#endif

#include <stdio_ext.h>

using crabc_stdio_permanent_fbufsize_stderr_signature = size_t (*)(FILE *);
static_assert(__is_same(decltype(&__fbufsize),
    crabc_stdio_permanent_fbufsize_stderr_signature),
    "__fbufsize C++ declaration");

__attribute__((used)) static crabc_stdio_permanent_fbufsize_stderr_signature
    crabc_stdio_permanent_fbufsize_stderr_reference = &__fbufsize;

int crabc_x86_64_stdio_permanent_fbufsize_stderr_header_abi_probe_cpp()
{
    return 0;
}
