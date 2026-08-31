/* Linux/x86-64 permanent-standard-stream fileno <stdio.h> declaration probe.
 *
 * This checks only POSIX-visible `int fileno(FILE *)`. Pinned musl 1.2.6 is
 * the declaration oracle. It neither selects a stdio runtime nor claims path
 * streams, descriptor adoption/reopen, byte/block I/O, unlocked APIs, or
 * public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_FILENO_C11) && \
    !defined(CRABC_STDIO_PERMANENT_FILENO_REQUIRE_HIDDEN)
#error "a permanent-stream fileno C11 profile must be selected"
#endif

#if __STDC_VERSION__ != 201112L
#error "this probe requires C11"
#endif

/* The negative strict witness deliberately leaves fileno hidden. */
#if !defined(CRABC_STDIO_PERMANENT_FILENO_REQUIRE_HIDDEN) && \
    !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>

#if defined(CRABC_STDIO_PERMANENT_FILENO_C11)
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE != 200809L
#error "the fileno C11 profile must retain _POSIX_C_SOURCE=200809L"
#endif

#define CRABC_STDIO_FILENO_ASSERT(name, condition) \
    typedef char name[(condition) ? 1 : -1]
#define CRABC_STDIO_FILENO_TYPE_IS(left, right) \
    __builtin_types_compatible_p(left, right)

typedef int (*crabc_stdio_permanent_fileno_signature)(FILE *);
CRABC_STDIO_FILENO_ASSERT(crabc_stdio_permanent_fileno_declaration,
    CRABC_STDIO_FILENO_TYPE_IS(__typeof__(&fileno),
        crabc_stdio_permanent_fileno_signature));
#endif

/* The runner expects this strict compile to fail because fileno is POSIX-only. */
#if defined(CRABC_STDIO_PERMANENT_FILENO_REQUIRE_HIDDEN)
static int (*crabc_stdio_permanent_fileno_hidden)(FILE *) = fileno;
#endif

int crabc_x86_64_stdio_permanent_fileno_header_abi_probe(void)
{
    return 0;
}
