/* C++17 companion to the Linux/x86-64 permanent-byte-I/O declaration probe.
 *
 * `used` references let the runner prove that <stdio.h> requests C ABI
 * spellings. This remains declaration-only evidence for the selected aliases
 * and one-byte `ungetc` signature.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_BYTE_IO_CXX17)
#error "the C++17 permanent-byte-I/O profile must be selected"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
#endif

#include <stdio.h>

using crabc_stdio_input_character_signature = int (*)(FILE *);
using crabc_stdio_getchar_signature = int (*)(void);
using crabc_stdio_output_character_signature = int (*)(int, FILE *);
using crabc_stdio_putchar_signature = int (*)(int);
using crabc_stdio_ungetc_signature = int (*)(int, FILE *);

static_assert(__is_same(decltype(&fgetc),
    crabc_stdio_input_character_signature), "fgetc C++ declaration");
static_assert(__is_same(decltype(&getc),
    crabc_stdio_input_character_signature), "getc C++ declaration");
static_assert(__is_same(decltype(&getchar),
    crabc_stdio_getchar_signature), "getchar C++ declaration");
static_assert(__is_same(decltype(&fputc),
    crabc_stdio_output_character_signature), "fputc C++ declaration");
static_assert(__is_same(decltype(&putc),
    crabc_stdio_output_character_signature), "putc C++ declaration");
static_assert(__is_same(decltype(&putchar),
    crabc_stdio_putchar_signature), "putchar C++ declaration");
static_assert(__is_same(decltype(&ungetc),
    crabc_stdio_ungetc_signature), "ungetc C++ declaration");

__attribute__((used)) static crabc_stdio_input_character_signature
    crabc_stdio_fgetc_reference = &fgetc;
__attribute__((used)) static crabc_stdio_input_character_signature
    crabc_stdio_getc_reference = &getc;
__attribute__((used)) static crabc_stdio_getchar_signature
    crabc_stdio_getchar_reference = &getchar;
__attribute__((used)) static crabc_stdio_output_character_signature
    crabc_stdio_fputc_reference = &fputc;
__attribute__((used)) static crabc_stdio_output_character_signature
    crabc_stdio_putc_reference = &putc;
__attribute__((used)) static crabc_stdio_putchar_signature
    crabc_stdio_putchar_reference = &putchar;
__attribute__((used)) static crabc_stdio_ungetc_signature
    crabc_stdio_ungetc_reference = &ungetc;

int crabc_x86_64_stdio_permanent_byte_io_header_abi_probe_cpp()
{
    return 0;
}
