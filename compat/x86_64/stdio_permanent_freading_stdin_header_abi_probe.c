/* Linux/x86-64 permanent-stdin __freading <stdio_ext.h> declaration probe.
 *
 * This checks only the unconditional int __freading(FILE *) declaration used
 * by the bounded read-direction observation. Pinned musl 1.2.6 is the
 * declaration oracle; it selects no input setup or general FILE model.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_FREADING_STDIN_C11)
#error "the permanent-stdin freading C11 profile must be selected"
#endif

#if __STDC_VERSION__ != 201112L
#error "this probe requires C11"
#endif

#include <stdio_ext.h>

#define CRABC_STDIO_FREADING_STDIN_ASSERT(name, condition) \
    typedef char name[(condition) ? 1 : -1]
#define CRABC_STDIO_FREADING_STDIN_TYPE_IS(left, right) \
    __builtin_types_compatible_p(left, right)

typedef int (*crabc_stdio_permanent_freading_stdin_signature)(FILE *);
CRABC_STDIO_FREADING_STDIN_ASSERT(
    crabc_stdio_permanent_freading_stdin_declaration,
    CRABC_STDIO_FREADING_STDIN_TYPE_IS(__typeof__(&__freading),
        crabc_stdio_permanent_freading_stdin_signature));

int crabc_x86_64_stdio_permanent_freading_stdin_header_abi_probe(void)
{
    return 0;
}
