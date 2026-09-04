#ifndef _STDLIB_H
#define _STDLIB_H

#include <features.h>

#define __NEED_size_t
#define __NEED_wchar_t
#include <bits/alltypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#if __cplusplus >= 201103L
#define NULL nullptr
#elif defined(__cplusplus)
#define NULL 0L
#else
#define NULL ((void*)0)
#endif

typedef struct { int quot, rem; } div_t;
typedef struct { long quot, rem; } ldiv_t;
typedef struct { long long quot, rem; } lldiv_t;

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

size_t __ctype_get_mb_cur_max(void);
#define MB_CUR_MAX (__ctype_get_mb_cur_max())

#define RAND_MAX (0x7fffffff)

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define WNOHANG 1
#define WUNTRACED 2
#ifndef WEXITSTATUS
#define WEXITSTATUS(s) (((s) & 0xff00) >> 8)
#endif
#ifndef WTERMSIG
#define WTERMSIG(s) ((s) & 0x7f)
#endif
#ifndef WSTOPSIG
#define WSTOPSIG(s) WEXITSTATUS(s)
#endif
#ifndef WIFEXITED
#if defined(__x86_64__)
#define WIFEXITED(s) (!WTERMSIG(s))
#else
#define WIFEXITED(s) (!(s & 0x7f))
#endif
#endif
#ifndef WIFSIGNALED
#define WIFSIGNALED(s) (((s)&0xffff)-1U < 0xffu)
#endif
#ifndef WIFSTOPPED
#define WIFSTOPPED(s) ((short)((((s)&0xffff)*0x10001U)>>8) > 0x7f00)
#endif
#endif

int atoi(const char *);
long atol(const char *);
long long atoll(const char *);
long strtol(const char *__restrict, char **__restrict, int);
unsigned long strtoul(const char *__restrict, char **__restrict, int);
long long strtoll(const char *__restrict, char **__restrict, int);
unsigned long long strtoull(const char *__restrict, char **__restrict, int);
double strtod(const char *__restrict, char **__restrict);
float strtof(const char *__restrict, char **__restrict);
long double strtold(const char *__restrict, char **__restrict);
double atof(const char *);

int abs(int);
long labs(long);
long long llabs(long long);

div_t div(int, int);
ldiv_t ldiv(long, long);
lldiv_t lldiv(long long, long long);

void srand(unsigned);
int rand(void);

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int rand_r(unsigned *);
#endif

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
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int posix_memalign(void **, size_t, size_t);
#endif

_Noreturn void abort(void);
int atexit(void (*)(void));
int at_quick_exit(void (*)(void));
_Noreturn void exit(int);
_Noreturn void _Exit(int);
_Noreturn void quick_exit(int);

char *getenv(const char *);
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int setenv(const char *, const char *, int);
int unsetenv(const char *);
#endif
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

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int getsubopt(char **, char *const *, char **);
char *mkdtemp(char *);
int mkstemp(char *);
int mkostemp(char *, int);
#endif
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
long a64l(const char *);
int grantpt(int);
char *l64a(long);
char *ptsname(int);
#endif

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
char *realpath(const char *__restrict, char *__restrict);
#endif
#if defined(_GNU_SOURCE)
int ptsname_r(int, char *, size_t);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#include <alloca.h>
#define WCOREDUMP(s) ((s) & 0x80)
#define WIFCONTINUED(s) ((s) == 0xffff)
char *mktemp(char *);
int mkstemps(char *, int);
int mkostemps(char *, int, int);
void *valloc(size_t);
void *memalign(size_t, size_t);
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
struct __locale_struct;
float strtof_l(const char *__restrict, char **__restrict, struct __locale_struct *);
double strtod_l(const char *__restrict, char **__restrict, struct __locale_struct *);
long double strtold_l(const char *__restrict, char **__restrict,
                      struct __locale_struct *);
#endif

#if defined(_LARGEFILE64_SOURCE)
#define mkstemp64 mkstemp
#define mkostemp64 mkostemp
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define mkstemps64 mkstemps
#define mkostemps64 mkostemps
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif
