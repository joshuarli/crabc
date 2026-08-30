/*
 * Linux/x86-64 permanent-standard-stream <stdio.h> declaration probe.
 *
 * This source selects only the public declaration/data/macro boundary needed
 * by the bounded permanent-standard-stream artifact.  Pinned musl 1.2.6 is
 * the oracle; the companion runner compiles both trees without linking an
 * archive.  It neither claims a stdio runtime, path streams, CRT lifecycle,
 * nor public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_STDIO_STANDARD_C99_STRICT) + \
    defined(CRABC_STDIO_STANDARD_C11_STRICT) + \
    defined(CRABC_STDIO_STANDARD_C11_POSIX_2008)) != 1
#error "select exactly one C stdio-standard profile"
#endif

#if defined(CRABC_STDIO_STANDARD_C99_STRICT) && \
    __STDC_VERSION__ != 199901L
#error "C99 strict profile requires C99"
#endif
#if (defined(CRABC_STDIO_STANDARD_C11_STRICT) || \
    defined(CRABC_STDIO_STANDARD_C11_POSIX_2008)) && \
    __STDC_VERSION__ != 201112L
#error "C11 stdio-standard profiles require C11"
#endif

#include <stdio.h>

#ifndef stdin
#error "stdio.h must define stdin as the standard-stream macro"
#endif
#ifndef stdout
#error "stdio.h must define stdout as the standard-stream macro"
#endif
#ifndef stderr
#error "stdio.h must define stderr as the standard-stream macro"
#endif

#if !defined(CRABC_STDIO_STANDARD_HIDDEN_WITNESS_ONLY)
#define CRABC_STDIO_ASSERT(name, condition) \
    typedef char name[(condition) ? 1 : -1]
#define CRABC_STDIO_TYPE_IS(left, right) \
    __builtin_types_compatible_p(left, right)

/* Musl exposes a complete one-byte opaque FILE only to pre-C11 consumers.
 * This must stay a public opacity boundary, never the private stream layout.
 */
#if defined(CRABC_STDIO_STANDARD_C99_STRICT)
CRABC_STDIO_ASSERT(crabc_stdio_c99_file_size, sizeof(FILE) == 1);
CRABC_STDIO_ASSERT(crabc_stdio_c99_file_align, __alignof__(FILE) == 1);
#endif

CRABC_STDIO_ASSERT(crabc_stdio_eof_value, EOF == -1);
CRABC_STDIO_ASSERT(crabc_stdio_buffer_size, BUFSIZ == 1024);
CRABC_STDIO_ASSERT(crabc_stdio_buffer_modes,
    _IOFBF == 0 && _IOLBF == 1 && _IONBF == 2);
CRABC_STDIO_ASSERT(crabc_stdio_seek_values,
    SEEK_SET == 0 && SEEK_CUR == 1 && SEEK_END == 2);

/* Test the public declarations rather than the macro-expanded lvalue type. */
#undef stdin
#undef stdout
#undef stderr

typedef FILE *const crabc_stdio_standard_stream_type;
typedef FILE *const *crabc_stdio_standard_stream_address_type;

CRABC_STDIO_ASSERT(crabc_stdio_stdin_data,
    CRABC_STDIO_TYPE_IS(__typeof__(&stdin),
        crabc_stdio_standard_stream_address_type));
CRABC_STDIO_ASSERT(crabc_stdio_stdout_data,
    CRABC_STDIO_TYPE_IS(__typeof__(&stdout),
        crabc_stdio_standard_stream_address_type));
CRABC_STDIO_ASSERT(crabc_stdio_stderr_data,
    CRABC_STDIO_TYPE_IS(__typeof__(&stderr),
        crabc_stdio_standard_stream_address_type));

typedef int (*crabc_stdio_fflush_signature)(FILE *);
typedef size_t (*crabc_stdio_fread_signature)(void *, size_t, size_t, FILE *);
typedef size_t (*crabc_stdio_fwrite_signature)(const void *, size_t, size_t,
    FILE *);
typedef int (*crabc_stdio_input_character_signature)(FILE *);
typedef int (*crabc_stdio_getchar_signature)(void);
typedef int (*crabc_stdio_output_character_signature)(int, FILE *);
typedef int (*crabc_stdio_putchar_signature)(int);
typedef int (*crabc_stdio_ungetc_signature)(int, FILE *);
typedef int (*crabc_stdio_stream_flag_signature)(FILE *);
typedef void (*crabc_stdio_clearerr_signature)(FILE *);

CRABC_STDIO_ASSERT(crabc_stdio_fflush_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&fflush), crabc_stdio_fflush_signature));
CRABC_STDIO_ASSERT(crabc_stdio_fread_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&fread), crabc_stdio_fread_signature));
CRABC_STDIO_ASSERT(crabc_stdio_fwrite_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&fwrite), crabc_stdio_fwrite_signature));
CRABC_STDIO_ASSERT(crabc_stdio_fgetc_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&fgetc),
        crabc_stdio_input_character_signature));
CRABC_STDIO_ASSERT(crabc_stdio_getc_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&getc),
        crabc_stdio_input_character_signature));
CRABC_STDIO_ASSERT(crabc_stdio_getchar_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&getchar), crabc_stdio_getchar_signature));
CRABC_STDIO_ASSERT(crabc_stdio_fputc_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&fputc),
        crabc_stdio_output_character_signature));
CRABC_STDIO_ASSERT(crabc_stdio_putc_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&putc),
        crabc_stdio_output_character_signature));
CRABC_STDIO_ASSERT(crabc_stdio_putchar_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&putchar), crabc_stdio_putchar_signature));
CRABC_STDIO_ASSERT(crabc_stdio_ungetc_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&ungetc), crabc_stdio_ungetc_signature));
CRABC_STDIO_ASSERT(crabc_stdio_feof_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&feof), crabc_stdio_stream_flag_signature));
CRABC_STDIO_ASSERT(crabc_stdio_ferror_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&ferror), crabc_stdio_stream_flag_signature));
CRABC_STDIO_ASSERT(crabc_stdio_clearerr_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&clearerr),
        crabc_stdio_clearerr_signature));

#if defined(CRABC_STDIO_STANDARD_C11_POSIX_2008)
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE != 200809L
#error "POSIX.1-2008 profile must retain _POSIX_C_SOURCE=200809L"
#endif
typedef int (*crabc_stdio_fileno_signature)(FILE *);
CRABC_STDIO_ASSERT(crabc_stdio_fileno_declaration,
    CRABC_STDIO_TYPE_IS(__typeof__(&fileno), crabc_stdio_fileno_signature));
#endif

#endif /* !CRABC_STDIO_STANDARD_HIDDEN_WITNESS_ONLY */

/* The runner compiles this strict-only mode expecting an undeclared-name
 * diagnostic. It is the direct negative proof that fileno remains POSIX-gated.
 */
#if defined(CRABC_STDIO_STANDARD_REQUIRE_FILENO_HIDDEN)
static int (*crabc_stdio_hidden_fileno)(FILE *) = fileno;
#endif

int crabc_x86_64_stdio_standard_header_abi_probe(void)
{
    return 0;
}
