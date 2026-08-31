/* C++17 companion to the GNU/BSD permanent-stream fileno_unlocked probe.
 *
 * `used` lets the runner verify the unmangled C spelling. Strict and POSIX
 * profiles remain declaration-negative, so this does not widen stdio headers.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_CXX17_GNU) && \
    !defined(CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_CXX17_BSD) && \
    !defined(CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_REQUIRE_HIDDEN)
#error "a permanent-stream fileno_unlocked C++17 profile must be selected"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
#endif

#include <stdio.h>

#if defined(CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_CXX17_GNU)
#if !defined(_GNU_SOURCE)
#error "the GNU fileno_unlocked C++17 profile must retain _GNU_SOURCE"
#endif
#elif defined(CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_CXX17_BSD)
#if !defined(_BSD_SOURCE)
#error "the BSD fileno_unlocked C++17 profile must retain _BSD_SOURCE"
#endif
#endif

#if defined(CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_CXX17_GNU) || \
    defined(CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_CXX17_BSD)
using crabc_stdio_permanent_fileno_unlocked_signature = int (*)(FILE *);
static_assert(__is_same(decltype(&fileno_unlocked),
    crabc_stdio_permanent_fileno_unlocked_signature),
    "fileno_unlocked C++ declaration");

__attribute__((used)) static crabc_stdio_permanent_fileno_unlocked_signature
    crabc_stdio_permanent_fileno_unlocked_reference = &fileno_unlocked;
#endif

/* The runner expects these strict/POSIX compiles to fail at this reference. */
#if defined(CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_REQUIRE_HIDDEN)
static int (*crabc_stdio_permanent_fileno_unlocked_hidden)(FILE *) =
    fileno_unlocked;
#endif

int crabc_x86_64_stdio_permanent_fileno_unlocked_header_abi_probe_cpp()
{
    return 0;
}
