/*
 * Direct x86 pinned-musl <stdio.h>/<stdio_ext.h> declaration-form checks.
 * This is intentionally compile-only: permanent stream providers remain
 * covered by their own feature gates and are not selected here.
 */
#include <stdio.h>
#include <stdio_ext.h>

#ifndef _STDIO_EXT_H
#error "x86 stdio_ext must retain musl's public guard"
#endif
#ifdef _CRABC_STDIO_EXT_H
#error "x86 stdio_ext must not retain the frozen non-x86 guard"
#endif

typedef FILE *(*crabc_fopen_type)(const char *__restrict, const char *__restrict);
typedef FILE *(*crabc_freopen_type)(const char *__restrict, const char *__restrict,
    FILE *__restrict);
typedef int (*crabc_fgetpos_type)(FILE *__restrict, fpos_t *__restrict);
typedef size_t (*crabc_fread_type)(void *__restrict, size_t, size_t,
    FILE *__restrict);
typedef size_t (*crabc_fwrite_type)(const void *__restrict, size_t, size_t,
    FILE *__restrict);
typedef char *(*crabc_fgets_type)(char *__restrict, int, FILE *__restrict);
typedef int (*crabc_fputs_type)(const char *__restrict, FILE *__restrict);
typedef int (*crabc_printf_type)(const char *__restrict, ...);
typedef int (*crabc_fprintf_type)(FILE *__restrict, const char *__restrict, ...);
typedef int (*crabc_vprintf_type)(const char *__restrict, __isoc_va_list);
typedef int (*crabc_vfprintf_type)(FILE *__restrict, const char *__restrict,
    __isoc_va_list);
typedef int (*crabc_setvbuf_type)(FILE *__restrict, char *__restrict, int, size_t);
typedef void (*crabc_setbuf_type)(FILE *__restrict, char *__restrict);

_Static_assert(__builtin_types_compatible_p(__typeof__(&fopen), crabc_fopen_type),
    "fopen restrict form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&freopen), crabc_freopen_type),
    "freopen restrict form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fgetpos), crabc_fgetpos_type),
    "fgetpos restrict form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fread), crabc_fread_type),
    "fread restrict form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fwrite), crabc_fwrite_type),
    "fwrite restrict form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fgets), crabc_fgets_type),
    "fgets restrict form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fputs), crabc_fputs_type),
    "fputs restrict form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&printf), crabc_printf_type),
    "printf restrict form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fprintf), crabc_fprintf_type),
    "fprintf restrict form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&vprintf), crabc_vprintf_type),
    "vprintf __isoc_va_list form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&vfprintf), crabc_vfprintf_type),
    "vfprintf __isoc_va_list form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setvbuf), crabc_setvbuf_type),
    "setvbuf restrict form");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setbuf), crabc_setbuf_type),
    "setbuf restrict form");

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
typedef int (*crabc_vdprintf_type)(int, const char *__restrict, __isoc_va_list);
_Static_assert(__builtin_types_compatible_p(__typeof__(&vdprintf), crabc_vdprintf_type),
    "vdprintf __isoc_va_list form");
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
typedef int (*crabc_asprintf_type)(char **, const char *, ...);
typedef int (*crabc_vasprintf_type)(char **, const char *, __isoc_va_list);
_Static_assert(__builtin_types_compatible_p(__typeof__(&asprintf), crabc_asprintf_type),
    "asprintf intentionally has no restrict qualifiers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&vasprintf), crabc_vasprintf_type),
    "vasprintf intentionally has no restrict qualifiers");
#endif

#if defined(_LARGEFILE64_SOURCE)
#ifndef fopen64
#error "fopen64 must remain a source alias"
#endif
#ifndef freopen64
#error "freopen64 must remain a source alias"
#endif
#endif

int crabc_x86_stdio_header_source_form_probe(void)
{
    return FSETLOCKING_QUERY;
}
