#ifndef _STDLIB_H
#define _STDLIB_H

#include <features.h>

#define __NEED_size_t
#define __NEED_wchar_t
#include <bits/alltypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#define NULL ((void*)0)
#endif

typedef struct { int quot, rem; } div_t;
typedef struct { long quot, rem; } ldiv_t;
typedef struct { long long quot, rem; } lldiv_t;

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
#define MB_LEN_MAX 4

size_t __ctype_get_mb_cur_max(void);
#define MB_CUR_MAX (__ctype_get_mb_cur_max())

#define RAND_MAX (0x7fffffff)

#ifndef WEXITSTATUS
#define WEXITSTATUS(s) (((s) & 0xff00) >> 8)
#endif
#ifndef WIFEXITED
#define WIFEXITED(s) (((s) & 0x7f) == 0)
#endif
#ifndef WIFSIGNALED
#define WIFSIGNALED(s) (((s) & 0x7f) != 0 && (((s) & 0x7f) != 0x7f))
#endif
#ifndef WTERMSIG
#define WTERMSIG(s) ((s) & 0x7f)
#endif
#define WIFSTOPPED(s) (((s) & 0xff) == 0x7f)
#define WSTOPSIG(s) WEXITSTATUS(s)
#define WIFCONTINUED(s) ((s) == 0xffff)
#define WNOHANG 1
#define WUNTRACED 2

int atoi(const char *);
long atol(const char *);
long long atoll(const char *);
long strtol(const char *, char **, int);
unsigned long strtoul(const char *, char **, int);
long long strtoll(const char *, char **, int);
unsigned long long strtoull(const char *, char **, int);
double strtod(const char *, char **);
float strtof(const char *, char **);
long double strtold(const char *, char **);
double atof(const char *);

int abs(int);
long labs(long);
long long llabs(long long);

div_t div(int, int);
ldiv_t ldiv(long, long);
lldiv_t lldiv(long long, long long);

void srand(unsigned);
int rand(void);

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
long lrand48(void);
long mrand48(void);
long nrand48(unsigned short *);
long jrand48(unsigned short *);
void srand48(long);
unsigned short *seed48(unsigned short *);
double drand48(void);
double erand48(unsigned short *);
void lcong48(unsigned short *);
void srandom(unsigned);
long random(void);
char *initstate(unsigned, char *, size_t);
char *setstate(char *);
#endif
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int getloadavg(double *, int);
#endif

void *malloc(size_t);
void *calloc(size_t, size_t);
void *realloc(void *, size_t);
void free(void *);
void *aligned_alloc(size_t, size_t);
int posix_memalign(void **, size_t, size_t);

_Noreturn void abort(void);
int atexit(void (*)(void));
int at_quick_exit(void (*)(void));
_Noreturn void exit(int);
_Noreturn void _Exit(int);
_Noreturn void quick_exit(int);

char *getenv(const char *);
int setenv(const char *, const char *, int);
int unsetenv(const char *);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int putenv(char *);
#endif
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int clearenv(void);
#endif

int system(const char *);

void *bsearch(const void *, const void *, size_t, size_t, int (*)(const void *, const void *));
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));

int mblen(const char *, size_t);
int mbtowc(wchar_t *__restrict, const char *__restrict, size_t);
int wctomb(char *, wchar_t);
size_t mbstowcs(wchar_t *__restrict, const char *__restrict, size_t);
size_t wcstombs(char *__restrict, const wchar_t *__restrict, size_t);

int getsubopt(char **, char *const *, char **);
char *mkdtemp(char *);
int mkstemp(char *);
int mkostemp(char *, int);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
long a64l(const char *);
int grantpt(int);
char *l64a(long);
char *ptsname(int);
#endif

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
char *realpath(const char *restrict, char *restrict);
#endif
#if defined(_GNU_SOURCE)
int ptsname_r(int, char *, size_t);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define WCOREDUMP(s) ((s) & 0x80)
void *reallocarray(void *, size_t, size_t);
void qsort_r(void *, size_t, size_t,
             int (*)(const void *, const void *, void *), void *);
#endif

#ifdef _GNU_SOURCE
char *secure_getenv(const char *);
#endif
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void setkey(const char *);
int unlockpt(int);
int posix_openpt(int);
#endif

#ifdef _GNU_SOURCE
char *ecvt(double, int, int *, int *);
char *fcvt(double, int, int *, int *);
char *gcvt(double, int, char *);
#endif

#ifdef __cplusplus
}
#endif

#endif
