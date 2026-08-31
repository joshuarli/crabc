/* Linux/x86-64 permanent-byte-I/O <stdio.h> declaration probe.
 *
 * This checks only the unconditional `fgetc`/`getc`/`getchar`,
 * `fputc`/`putc`/`putchar`, and one-byte `ungetc` C declarations needed by
 * the bounded permanent-standard-stream artifact. Pinned musl 1.2.6 is the
 * declaration oracle. It neither selects a stdio runtime nor claims pathname,
 * descriptor, tmpfile, LFS, or public-x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_BYTE_IO_C11)
#error "the C11 permanent-byte-I/O profile must be selected"
#endif

#if __STDC_VERSION__ != 201112L
#error "this probe requires C11"
#endif

#include <stdio.h>

#define CRABC_STDIO_BYTE_IO_ASSERT(name, condition) \
    typedef char name[(condition) ? 1 : -1]
#define CRABC_STDIO_BYTE_IO_TYPE_IS(left, right) \
    __builtin_types_compatible_p(left, right)

typedef int (*crabc_stdio_input_character_signature)(FILE *);
typedef int (*crabc_stdio_getchar_signature)(void);
typedef int (*crabc_stdio_output_character_signature)(int, FILE *);
typedef int (*crabc_stdio_putchar_signature)(int);
typedef int (*crabc_stdio_ungetc_signature)(int, FILE *);

CRABC_STDIO_BYTE_IO_ASSERT(crabc_stdio_fgetc_declaration,
    CRABC_STDIO_BYTE_IO_TYPE_IS(__typeof__(&fgetc),
        crabc_stdio_input_character_signature));
CRABC_STDIO_BYTE_IO_ASSERT(crabc_stdio_getc_declaration,
    CRABC_STDIO_BYTE_IO_TYPE_IS(__typeof__(&getc),
        crabc_stdio_input_character_signature));
CRABC_STDIO_BYTE_IO_ASSERT(crabc_stdio_getchar_declaration,
    CRABC_STDIO_BYTE_IO_TYPE_IS(__typeof__(&getchar),
        crabc_stdio_getchar_signature));
CRABC_STDIO_BYTE_IO_ASSERT(crabc_stdio_fputc_declaration,
    CRABC_STDIO_BYTE_IO_TYPE_IS(__typeof__(&fputc),
        crabc_stdio_output_character_signature));
CRABC_STDIO_BYTE_IO_ASSERT(crabc_stdio_putc_declaration,
    CRABC_STDIO_BYTE_IO_TYPE_IS(__typeof__(&putc),
        crabc_stdio_output_character_signature));
CRABC_STDIO_BYTE_IO_ASSERT(crabc_stdio_putchar_declaration,
    CRABC_STDIO_BYTE_IO_TYPE_IS(__typeof__(&putchar),
        crabc_stdio_putchar_signature));
CRABC_STDIO_BYTE_IO_ASSERT(crabc_stdio_ungetc_declaration,
    CRABC_STDIO_BYTE_IO_TYPE_IS(__typeof__(&ungetc),
        crabc_stdio_ungetc_signature));

int crabc_x86_64_stdio_permanent_byte_io_header_abi_probe(void)
{
    return 0;
}
