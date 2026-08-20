#ifndef _WCHAR_H
#define _WCHAR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <locale.h>
#include <time.h>

#ifndef NULL
#ifndef NULL
#define NULL ((void*)0)
#endif
#endif

#ifndef WEOF
#define WEOF 0xffffffffU
#endif
#define WCHAR_MIN 0
#define WCHAR_MAX 4294967295U

#ifndef __cplusplus
#if defined(__aarch64__)
typedef unsigned int wchar_t;
#elif defined(__riscv)
typedef int wchar_t;
#else
typedef int wchar_t;
#endif
#endif
typedef unsigned int wint_t;
typedef unsigned int mbstate_t;

/* Wide string functions */
size_t wcslen(const wchar_t *);
wchar_t *wcscpy(wchar_t *, const wchar_t *);
wchar_t *wcsncpy(wchar_t *, const wchar_t *, size_t);
wchar_t *wcscat(wchar_t *, const wchar_t *);
wchar_t *wcsncat(wchar_t *, const wchar_t *, size_t);
int wcscmp(const wchar_t *, const wchar_t *);
int wcsncmp(const wchar_t *, const wchar_t *, size_t);
wchar_t *wcschr(const wchar_t *, wchar_t);
wchar_t *wcsrchr(const wchar_t *, wchar_t);
wchar_t *wcsstr(const wchar_t *, const wchar_t *);
size_t wcscspn(const wchar_t *, const wchar_t *);
size_t wcsspn(const wchar_t *, const wchar_t *);
wchar_t *wcspbrk(const wchar_t *, const wchar_t *);
wchar_t *wcsdup(const wchar_t *);
size_t wcsnlen(const wchar_t *, size_t);
size_t wcsxfrm(wchar_t *, const wchar_t *, size_t);
int wcscoll(const wchar_t *, const wchar_t *);
size_t wcsftime(wchar_t *restrict, size_t, const wchar_t *restrict, const struct tm *restrict);
size_t wcsftime_l(wchar_t *restrict, size_t, const wchar_t *restrict, const struct tm *restrict, locale_t);
wchar_t *wcstok(wchar_t *restrict, const wchar_t *restrict, wchar_t **restrict);

/* Multibyte/wide conversions */
wint_t btowc(int);
int wctob(wint_t);
int mbsinit(const mbstate_t *);
size_t mbrtowc(wchar_t *, const char *, size_t, mbstate_t *);
size_t wcrtomb(char *, wchar_t, mbstate_t *);
size_t mbrlen(const char *, size_t, mbstate_t *);
size_t mbsrtowcs(wchar_t *, const char **, size_t, mbstate_t *);
size_t wcsrtombs(char *, const wchar_t **, size_t, mbstate_t *);
size_t mbsnrtowcs(wchar_t *restrict, const char **restrict, size_t, size_t, mbstate_t *restrict);
size_t wcsnrtombs(char *restrict, const wchar_t **restrict, size_t, size_t, mbstate_t *restrict);
size_t mbstowcs(wchar_t *, const char *, size_t);
size_t wcstombs(char *, const wchar_t *, size_t);

/* Wide number conversions */
long wcstol(const wchar_t *, wchar_t **, int);
unsigned long wcstoul(const wchar_t *, wchar_t **, int);
long long wcstoll(const wchar_t *, wchar_t **, int);
unsigned long long wcstoull(const wchar_t *, wchar_t **, int);
double wcstod(const wchar_t *, wchar_t **);
float wcstof(const wchar_t *, wchar_t **);
long double wcstold(const wchar_t *, wchar_t **);
long wcstoimax(const wchar_t *, wchar_t **, int);
unsigned long wcstoumax(const wchar_t *, wchar_t **, int);

/* Wide stdio */
wint_t fgetwc(FILE *);
wchar_t *fgetws(wchar_t *restrict, int, FILE *restrict);
wchar_t *fgetws_unlocked(wchar_t *restrict, int, FILE *restrict);
wint_t getwchar(void);
wint_t fputwc(wchar_t, FILE *);
wint_t putwchar(wchar_t);
int fputws(const wchar_t *, FILE *);
wint_t ungetwc(wint_t, FILE *);
FILE *open_wmemstream(wchar_t **, size_t *);
int fwide(FILE *, int);
wint_t getwc(FILE *);
wint_t putwc(wchar_t, FILE *);

/* Wide printf */
int swprintf(wchar_t *, size_t, const wchar_t *, ...);
int vswprintf(wchar_t *, size_t, const wchar_t *, va_list);
int fwprintf(FILE *, const wchar_t *, ...);
int vfwprintf(FILE *, const wchar_t *, va_list);
int wprintf(const wchar_t *restrict, ...);
int vwprintf(const wchar_t *restrict, va_list);
int vwscanf(const wchar_t *restrict, va_list);

/* Wide scanf */
int wscanf(const wchar_t *, ...);
int fwscanf(FILE *, const wchar_t *, ...);
int swscanf(const wchar_t *, const wchar_t *, ...);
int vwscanf(const wchar_t *, va_list);
int vfwscanf(FILE *, const wchar_t *, va_list);
int vswscanf(const wchar_t *, const wchar_t *, va_list);

wchar_t *wmemchr(const wchar_t *, wchar_t, size_t);
int wmemcmp(const wchar_t *, const wchar_t *, size_t);
wchar_t *wmemcpy(wchar_t *restrict, const wchar_t *restrict, size_t);
wchar_t *wmemmove(wchar_t *, const wchar_t *, size_t);
wchar_t *wmemset(wchar_t *, wchar_t, size_t);
wchar_t *wcpcpy(wchar_t *restrict, const wchar_t *restrict);
wchar_t *wcpncpy(wchar_t *restrict, const wchar_t *restrict, size_t);
int wcscasecmp(const wchar_t *, const wchar_t *);
int wcscasecmp_l(const wchar_t *, const wchar_t *, locale_t);
int wcscoll_l(const wchar_t *, const wchar_t *, locale_t);
int wcsncasecmp(const wchar_t *, const wchar_t *, size_t);
int wcsncasecmp_l(const wchar_t *, const wchar_t *, size_t, locale_t);
size_t wcsxfrm_l(wchar_t *restrict, const wchar_t *restrict, size_t, locale_t);
int wcswidth(const wchar_t *, size_t);
int wcwidth(wchar_t);

#ifdef __cplusplus
}
#endif

#endif
