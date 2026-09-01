/* Linux/x86-64 permanent-standard-stream ferror_unlocked header probe.
 *
 * Pinned musl 1.2.6 exposes this weak alias only in GNU/BSD profiles. This
 * checks the exact `int ferror_unlocked(FILE *)` declaration and keeps strict
 * and POSIX profiles negative. It selects no runtime or general FILE model.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_FERROR_UNLOCKED_C11_GNU) && \
    !defined(CRABC_STDIO_PERMANENT_FERROR_UNLOCKED_C11_BSD) && \
    !defined(CRABC_STDIO_PERMANENT_FERROR_UNLOCKED_REQUIRE_HIDDEN)
#error "a permanent-stream ferror_unlocked C11 profile must be selected"
#endif

#if __STDC_VERSION__ != 201112L
#error "this probe requires C11"
#endif

#include <stdio.h>

#if defined(CRABC_STDIO_PERMANENT_FERROR_UNLOCKED_C11_GNU)
#if !defined(_GNU_SOURCE)
#error "the GNU ferror_unlocked C11 profile must retain _GNU_SOURCE"
#endif
#elif defined(CRABC_STDIO_PERMANENT_FERROR_UNLOCKED_C11_BSD)
#if !defined(_BSD_SOURCE)
#error "the BSD ferror_unlocked C11 profile must retain _BSD_SOURCE"
#endif
#endif

#if defined(CRABC_STDIO_PERMANENT_FERROR_UNLOCKED_C11_GNU) || \
    defined(CRABC_STDIO_PERMANENT_FERROR_UNLOCKED_C11_BSD)
#define CRABC_STDIO_FERROR_UNLOCKED_ASSERT(name, condition) \
    typedef char name[(condition) ? 1 : -1]
#define CRABC_STDIO_FERROR_UNLOCKED_TYPE_IS(left, right) \
    __builtin_types_compatible_p(left, right)

typedef int (*crabc_stdio_permanent_ferror_unlocked_signature)(FILE *);
CRABC_STDIO_FERROR_UNLOCKED_ASSERT(
    crabc_stdio_permanent_ferror_unlocked_declaration,
    CRABC_STDIO_FERROR_UNLOCKED_TYPE_IS(__typeof__(&ferror_unlocked),
        crabc_stdio_permanent_ferror_unlocked_signature));
#endif

/* The runner expects these strict/POSIX compiles to fail at this reference. */
#if defined(CRABC_STDIO_PERMANENT_FERROR_UNLOCKED_REQUIRE_HIDDEN)
static int (*crabc_stdio_permanent_ferror_unlocked_hidden)(FILE *) =
    ferror_unlocked;
#endif

int crabc_x86_64_stdio_permanent_ferror_unlocked_header_abi_probe(void)
{
    return 0;
}
