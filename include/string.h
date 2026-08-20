#ifndef _STRING_H
#define _STRING_H

#include <features.h>
#define __NEED_size_t
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define __NEED_locale_t
#endif
#include <bits/alltypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
void *memchr(const void *, int, size_t);

size_t strlen(const char *);
char *strcpy(char *, const char *);
char *strncpy(char *, const char *, size_t);
char *strcat(char *, const char *);
char *strncat(char *, const char *, size_t);
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);
char *strchr(const char *, int);
char *strrchr(const char *, int);
size_t strspn(const char *, const char *);
size_t strcspn(const char *, const char *);
char *strpbrk(const char *, const char *);
char *strstr(const char *, const char *);
char *strtok(char *, const char *);
int strcoll(const char *, const char *);
size_t strxfrm(char *, const char *, size_t);

char *strerror(int);

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
char *strtok_r(char *restrict, const char *restrict, char **restrict);
char *stpcpy(char *restrict, const char *restrict);
char *stpncpy(char *restrict, const char *restrict, size_t);
size_t strnlen(const char *, size_t);
char *strdup(const char *);
char *strndup(const char *, size_t);
char *strsignal(int);
char *strerror_l(int, locale_t);
int strcoll_l(const char *, const char *, locale_t);
size_t strxfrm_l(char *, const char *, size_t, locale_t);
void *memmem(const void *, size_t, const void *, size_t);
int strerror_r(int, char *, size_t);
#endif

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void *memccpy(void *restrict, const void *restrict, int, size_t);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
char *strsep(char **, const char *);
size_t strlcpy(char *, const char *, size_t);
size_t strlcat(char *, const char *, size_t);
void explicit_bzero(void *, size_t);
#endif

#ifdef _GNU_SOURCE
char *strcasestr(const char *, const char *);
void *memrchr(const void *, int, size_t);
void *mempcpy(void *restrict, const void *, size_t);
#endif

#ifdef __cplusplus
}
#endif

#endif
