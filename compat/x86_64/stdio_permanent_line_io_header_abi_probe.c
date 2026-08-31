/* Linux/x86-64 permanent-line-I/O <stdio.h> declaration probe.
 *
 * This checks only the unconditional `fgets`, `fputs`, and `puts` C
 * declarations needed by the bounded permanent-standard-stream artifact.
 * Pinned musl 1.2.6 is the declaration oracle. It neither selects a stdio
 * runtime nor claims pathname, descriptor, tmpfile, LFS, or public-x86
 * support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_LINE_IO_C11)
#error "the C11 permanent-line-I/O profile must be selected"
#endif

#if __STDC_VERSION__ != 201112L
#error "this probe requires C11"
#endif

#include <stdio.h>

#define CRABC_STDIO_LINE_IO_ASSERT(name, condition) \
    typedef char name[(condition) ? 1 : -1]
#define CRABC_STDIO_LINE_IO_TYPE_IS(left, right) \
    __builtin_types_compatible_p(left, right)

typedef char *(*crabc_stdio_fgets_signature)(char *, int, FILE *);
typedef int (*crabc_stdio_fputs_signature)(const char *, FILE *);
typedef int (*crabc_stdio_puts_signature)(const char *);

CRABC_STDIO_LINE_IO_ASSERT(crabc_stdio_fgets_declaration,
    CRABC_STDIO_LINE_IO_TYPE_IS(__typeof__(&fgets),
        crabc_stdio_fgets_signature));
CRABC_STDIO_LINE_IO_ASSERT(crabc_stdio_fputs_declaration,
    CRABC_STDIO_LINE_IO_TYPE_IS(__typeof__(&fputs),
        crabc_stdio_fputs_signature));
CRABC_STDIO_LINE_IO_ASSERT(crabc_stdio_puts_declaration,
    CRABC_STDIO_LINE_IO_TYPE_IS(__typeof__(&puts),
        crabc_stdio_puts_signature));

int crabc_x86_64_stdio_permanent_line_io_header_abi_probe(void)
{
    return 0;
}
