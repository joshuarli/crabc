// Direct x86 pinned-musl <stdio.h>/<stdio_ext.h> declaration and C-linkage checks.
#include <stdio.h>
#include <stdio_ext.h>

#ifndef _STDIO_EXT_H
#error "x86 stdio_ext must retain musl's public guard"
#endif
#ifdef _CRABC_STDIO_EXT_H
#error "x86 stdio_ext must not retain the frozen non-x86 guard"
#endif

using crabc_fopen_type = FILE *(*)(const char *__restrict, const char *__restrict);
using crabc_freopen_type = FILE *(*)(const char *__restrict, const char *__restrict,
    FILE *__restrict);
using crabc_fgetpos_type = int (*)(FILE *__restrict, fpos_t *__restrict);
using crabc_fread_type = size_t (*)(void *__restrict, size_t, size_t, FILE *__restrict);
using crabc_fwrite_type = size_t (*)(const void *__restrict, size_t, size_t,
    FILE *__restrict);
using crabc_fgets_type = char *(*)(char *__restrict, int, FILE *__restrict);
using crabc_fputs_type = int (*)(const char *__restrict, FILE *__restrict);
using crabc_printf_type = int (*)(const char *__restrict, ...);
using crabc_fprintf_type = int (*)(FILE *__restrict, const char *__restrict, ...);
using crabc_vprintf_type = int (*)(const char *__restrict, __isoc_va_list);
using crabc_vfprintf_type = int (*)(FILE *__restrict, const char *__restrict,
    __isoc_va_list);
using crabc_setvbuf_type = int (*)(FILE *__restrict, char *__restrict, int, size_t);
using crabc_setbuf_type = void (*)(FILE *__restrict, char *__restrict);

static_assert(__is_same(decltype(&fopen), crabc_fopen_type));
static_assert(__is_same(decltype(&freopen), crabc_freopen_type));
static_assert(__is_same(decltype(&fgetpos), crabc_fgetpos_type));
static_assert(__is_same(decltype(&fread), crabc_fread_type));
static_assert(__is_same(decltype(&fwrite), crabc_fwrite_type));
static_assert(__is_same(decltype(&fgets), crabc_fgets_type));
static_assert(__is_same(decltype(&fputs), crabc_fputs_type));
static_assert(__is_same(decltype(&printf), crabc_printf_type));
static_assert(__is_same(decltype(&fprintf), crabc_fprintf_type));
static_assert(__is_same(decltype(&vprintf), crabc_vprintf_type));
static_assert(__is_same(decltype(&vfprintf), crabc_vfprintf_type));
static_assert(__is_same(decltype(&setvbuf), crabc_setvbuf_type));
static_assert(__is_same(decltype(&setbuf), crabc_setbuf_type));

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
using crabc_vdprintf_type = int (*)(int, const char *__restrict, __isoc_va_list);
static_assert(__is_same(decltype(&vdprintf), crabc_vdprintf_type));
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
using crabc_asprintf_type = int (*)(char **, const char *, ...);
using crabc_vasprintf_type = int (*)(char **, const char *, __isoc_va_list);
static_assert(__is_same(decltype(&asprintf), crabc_asprintf_type));
static_assert(__is_same(decltype(&vasprintf), crabc_vasprintf_type));
static int (*volatile crabc_asprintf_reference)(char **, const char *, ...) = &asprintf;
static int (*volatile crabc_vasprintf_reference)(char **, const char *, __isoc_va_list) =
    &vasprintf;
#endif

#if defined(_LARGEFILE64_SOURCE)
#ifndef fopen64
#error "fopen64 must remain a source alias"
#endif
#ifndef freopen64
#error "freopen64 must remain a source alias"
#endif
#endif

static FILE *(*volatile crabc_fopen_reference)(const char *__restrict,
    const char *__restrict) = &fopen;
static FILE *(*volatile crabc_freopen_reference)(const char *__restrict,
    const char *__restrict, FILE *__restrict) = &freopen;
static int (*volatile crabc_printf_reference)(const char *__restrict, ...) = &printf;
static int (*volatile crabc_vprintf_reference)(const char *__restrict, __isoc_va_list) =
    &vprintf;
static int (*volatile crabc_fsetlocking_reference)(FILE *, int) = &__fsetlocking;
static size_t (*volatile crabc_fbufsize_reference)(FILE *) = &__fbufsize;

extern "C" int crabc_x86_stdio_header_source_form_probe_cpp(void)
{
    int present = crabc_fopen_reference != nullptr && crabc_freopen_reference != nullptr &&
        crabc_printf_reference != nullptr && crabc_vprintf_reference != nullptr &&
        crabc_fsetlocking_reference != nullptr && crabc_fbufsize_reference != nullptr;
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
    present = present && crabc_asprintf_reference != nullptr &&
        crabc_vasprintf_reference != nullptr;
#endif
    return present ? FSETLOCKING_QUERY : FSETLOCKING_BYCALLER;
}
