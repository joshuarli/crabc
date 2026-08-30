/*
 * C++17 companion to the Linux/x86-64 permanent-standard-stream <stdio.h>
 * declaration probe. `used` references let the runner verify that the header
 * requested unmangled C spellings without linking a libc archive.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if (defined(CRABC_STDIO_STANDARD_CXX17_STRICT) + \
    defined(CRABC_STDIO_STANDARD_CXX17_POSIX_2008)) != 1
#error "select exactly one C++ stdio-standard profile"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
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
static_assert(EOF == -1, "EOF value");
static_assert(BUFSIZ == 1024, "BUFSIZ value");
static_assert(_IOFBF == 0 && _IOLBF == 1 && _IONBF == 2,
    "stream buffering mode values");
static_assert(SEEK_SET == 0 && SEEK_CUR == 1 && SEEK_END == 2,
    "stream seek value macros");

/* The C++ public FILE is deliberately opaque. Verify only pointer/data ABI,
 * not the private implementation's stream-state representation.
 */
#undef stdin
#undef stdout
#undef stderr

using crabc_stdio_standard_stream_type = FILE *const;
using crabc_stdio_standard_stream_address_type = FILE *const *;
static_assert(__is_same(decltype(&stdin),
    crabc_stdio_standard_stream_address_type), "stdin C++ data declaration");
static_assert(__is_same(decltype(&stdout),
    crabc_stdio_standard_stream_address_type), "stdout C++ data declaration");
static_assert(__is_same(decltype(&stderr),
    crabc_stdio_standard_stream_address_type), "stderr C++ data declaration");

using crabc_stdio_fflush_signature = int (*)(FILE *);
using crabc_stdio_fread_signature = size_t (*)(void *, size_t, size_t, FILE *);
using crabc_stdio_fwrite_signature = size_t (*)(const void *, size_t, size_t,
    FILE *);
using crabc_stdio_input_character_signature = int (*)(FILE *);
using crabc_stdio_getchar_signature = int (*)(void);
using crabc_stdio_output_character_signature = int (*)(int, FILE *);
using crabc_stdio_putchar_signature = int (*)(int);
using crabc_stdio_ungetc_signature = int (*)(int, FILE *);
using crabc_stdio_stream_flag_signature = int (*)(FILE *);
using crabc_stdio_clearerr_signature = void (*)(FILE *);

static_assert(__is_same(decltype(&fflush), crabc_stdio_fflush_signature),
    "fflush C++ declaration");
static_assert(__is_same(decltype(&fread), crabc_stdio_fread_signature),
    "fread C++ declaration");
static_assert(__is_same(decltype(&fwrite), crabc_stdio_fwrite_signature),
    "fwrite C++ declaration");
static_assert(__is_same(decltype(&fgetc),
    crabc_stdio_input_character_signature), "fgetc C++ declaration");
static_assert(__is_same(decltype(&getc),
    crabc_stdio_input_character_signature), "getc C++ declaration");
static_assert(__is_same(decltype(&getchar), crabc_stdio_getchar_signature),
    "getchar C++ declaration");
static_assert(__is_same(decltype(&fputc),
    crabc_stdio_output_character_signature), "fputc C++ declaration");
static_assert(__is_same(decltype(&putc),
    crabc_stdio_output_character_signature), "putc C++ declaration");
static_assert(__is_same(decltype(&putchar), crabc_stdio_putchar_signature),
    "putchar C++ declaration");
static_assert(__is_same(decltype(&ungetc), crabc_stdio_ungetc_signature),
    "ungetc C++ declaration");
static_assert(__is_same(decltype(&feof), crabc_stdio_stream_flag_signature),
    "feof C++ declaration");
static_assert(__is_same(decltype(&ferror), crabc_stdio_stream_flag_signature),
    "ferror C++ declaration");
static_assert(__is_same(decltype(&clearerr), crabc_stdio_clearerr_signature),
    "clearerr C++ declaration");

__attribute__((used)) static crabc_stdio_standard_stream_address_type
    crabc_stdio_stdin_reference = &stdin;
__attribute__((used)) static crabc_stdio_standard_stream_address_type
    crabc_stdio_stdout_reference = &stdout;
__attribute__((used)) static crabc_stdio_standard_stream_address_type
    crabc_stdio_stderr_reference = &stderr;
__attribute__((used)) static crabc_stdio_fflush_signature
    crabc_stdio_fflush_reference = &fflush;
__attribute__((used)) static crabc_stdio_fread_signature
    crabc_stdio_fread_reference = &fread;
__attribute__((used)) static crabc_stdio_fwrite_signature
    crabc_stdio_fwrite_reference = &fwrite;
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
__attribute__((used)) static crabc_stdio_stream_flag_signature
    crabc_stdio_feof_reference = &feof;
__attribute__((used)) static crabc_stdio_stream_flag_signature
    crabc_stdio_ferror_reference = &ferror;
__attribute__((used)) static crabc_stdio_clearerr_signature
    crabc_stdio_clearerr_reference = &clearerr;

#if defined(CRABC_STDIO_STANDARD_CXX17_POSIX_2008)
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE != 200809L
#error "POSIX.1-2008 profile must retain _POSIX_C_SOURCE=200809L"
#endif
using crabc_stdio_fileno_signature = int (*)(FILE *);
static_assert(__is_same(decltype(&fileno), crabc_stdio_fileno_signature),
    "fileno C++ declaration");
__attribute__((used)) static crabc_stdio_fileno_signature
    crabc_stdio_fileno_reference = &fileno;
#endif

#endif /* !CRABC_STDIO_STANDARD_HIDDEN_WITNESS_ONLY */

/* Strict profiles must reject the POSIX-only declaration. */
#if defined(CRABC_STDIO_STANDARD_REQUIRE_FILENO_HIDDEN)
static int (*crabc_stdio_hidden_fileno)(FILE *) = fileno;
#endif
