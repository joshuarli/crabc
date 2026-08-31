/* Linux/x86-64 permanent-stdin __fsetlocking <stdio_ext.h> declaration probe.
 *
 * This checks the unconditional int __fsetlocking(FILE *, int) declaration
 * and the three named request constants used by the bounded no-op adapter.
 * Pinned musl 1.2.6 is the declaration oracle; no lock or FILE model runs.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_FSETLOCKING_STDIN_C11)
#error "the permanent-stdin fsetlocking C11 profile must be selected"
#endif

#if __STDC_VERSION__ != 201112L
#error "this probe requires C11"
#endif

#include <stdio_ext.h>

#define CRABC_STDIO_FSETLOCKING_STDIN_ASSERT(name, condition) \
    typedef char name[(condition) ? 1 : -1]
#define CRABC_STDIO_FSETLOCKING_STDIN_TYPE_IS(left, right) \
    __builtin_types_compatible_p(left, right)

typedef int (*crabc_stdio_permanent_fsetlocking_stdin_signature)(FILE *, int);
CRABC_STDIO_FSETLOCKING_STDIN_ASSERT(
    crabc_stdio_permanent_fsetlocking_stdin_declaration,
    CRABC_STDIO_FSETLOCKING_STDIN_TYPE_IS(__typeof__(&__fsetlocking),
        crabc_stdio_permanent_fsetlocking_stdin_signature));
CRABC_STDIO_FSETLOCKING_STDIN_ASSERT(
    crabc_stdio_permanent_fsetlocking_query_value,
    FSETLOCKING_QUERY == 0);
CRABC_STDIO_FSETLOCKING_STDIN_ASSERT(
    crabc_stdio_permanent_fsetlocking_internal_value,
    FSETLOCKING_INTERNAL == 1);
CRABC_STDIO_FSETLOCKING_STDIN_ASSERT(
    crabc_stdio_permanent_fsetlocking_bycaller_value,
    FSETLOCKING_BYCALLER == 2);

int crabc_x86_64_stdio_permanent_fsetlocking_stdin_header_abi_probe(void)
{
    return 0;
}
