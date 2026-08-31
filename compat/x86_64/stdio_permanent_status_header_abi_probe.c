/* Linux/x86-64 permanent-stream status <stdio.h> declaration probe.
 *
 * This checks only the unconditional `feof`/`ferror`/`clearerr` C
 * declarations needed by the bounded permanent-standard-stream status leaf.
 * Pinned musl 1.2.6 is the declaration oracle. It neither selects a stdio
 * runtime nor claims pathname, descriptor, byte/block, unlocked, or public-x86
 * support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_STATUS_C11)
#error "the C11 permanent-stream-status profile must be selected"
#endif

#if __STDC_VERSION__ != 201112L
#error "this probe requires C11"
#endif

#include <stdio.h>

#define CRABC_STDIO_STATUS_ASSERT(name, condition) \
    typedef char name[(condition) ? 1 : -1]
#define CRABC_STDIO_STATUS_TYPE_IS(left, right) \
    __builtin_types_compatible_p(left, right)

typedef int (*crabc_stdio_status_predicate_signature)(FILE *);
typedef void (*crabc_stdio_status_clear_signature)(FILE *);

CRABC_STDIO_STATUS_ASSERT(crabc_stdio_feof_declaration,
    CRABC_STDIO_STATUS_TYPE_IS(__typeof__(&feof),
        crabc_stdio_status_predicate_signature));
CRABC_STDIO_STATUS_ASSERT(crabc_stdio_ferror_declaration,
    CRABC_STDIO_STATUS_TYPE_IS(__typeof__(&ferror),
        crabc_stdio_status_predicate_signature));
CRABC_STDIO_STATUS_ASSERT(crabc_stdio_clearerr_declaration,
    CRABC_STDIO_STATUS_TYPE_IS(__typeof__(&clearerr),
        crabc_stdio_status_clear_signature));

int crabc_x86_64_stdio_permanent_status_header_abi_probe(void)
{
    return 0;
}
