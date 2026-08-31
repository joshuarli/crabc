/* C++17 companion to the Linux/x86-64 permanent-stream fileno probe.
 *
 * `used` retains the reference so the runner can prove that <stdio.h> requests
 * the unmangled C spelling. This is declaration-only evidence and selects no
 * runtime or general FILE model.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_FILENO_CXX17) && \
    !defined(CRABC_STDIO_PERMANENT_FILENO_REQUIRE_HIDDEN)
#error "a permanent-stream fileno C++17 profile must be selected"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
#endif

/* The negative strict witness deliberately leaves fileno hidden. */
#if !defined(CRABC_STDIO_PERMANENT_FILENO_REQUIRE_HIDDEN) && \
    !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>

#if defined(CRABC_STDIO_PERMANENT_FILENO_CXX17)
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE != 200809L
#error "the fileno C++17 profile must retain _POSIX_C_SOURCE=200809L"
#endif

using crabc_stdio_permanent_fileno_signature = int (*)(FILE *);
static_assert(__is_same(decltype(&fileno),
    crabc_stdio_permanent_fileno_signature), "fileno C++ declaration");

__attribute__((used)) static crabc_stdio_permanent_fileno_signature
    crabc_stdio_permanent_fileno_reference = &fileno;
#endif

/* The runner expects this strict compile to fail because fileno is POSIX-only. */
#if defined(CRABC_STDIO_PERMANENT_FILENO_REQUIRE_HIDDEN)
static int (*crabc_stdio_permanent_fileno_hidden)(FILE *) = fileno;
#endif

int crabc_x86_64_stdio_permanent_fileno_header_abi_probe_cpp()
{
    return 0;
}
