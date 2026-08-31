#ifndef _STDIO_H
#define _STDIO_H

#include <features.h>

#define __NEED_FILE
/*
 * C11 permits FILE to remain incomplete.  Earlier C modes must be able to
 * form the historical one-byte opaque object, matching musl's public header
 * contract without exposing the target-private stream state used by libc.
 */
#if __STDC_VERSION__ < 201112L
#define __NEED_struct__IO_FILE
#endif
#define __NEED_size_t
#define __NEED___isoc_va_list
#define __NEED_va_list
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define __NEED_ssize_t
#define __NEED_off_t
#endif
#include <bits/alltypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * musl's fpos_t is intentionally a 16-byte opaque value.  The first eight
 * bytes carry the file offset today, while the union's array/alignment arms
 * keep the public ABI stable for callers that store or pass fpos_t objects.
 */
typedef union {
    char __opaque[16];
    long long __lldata;
    double __align;
} fpos_t;

extern FILE *const stdin;
extern FILE *const stdout;
extern FILE *const stderr;

#define stdin (stdin)
#define stdout (stdout)
#define stderr (stderr)

#if __cplusplus >= 201103L
#define NULL nullptr
#elif defined(__cplusplus)
#define NULL 0L
#else
#define NULL ((void*)0)
#endif
#define EOF (-1)

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define _IOFBF 0
#define _IOLBF 1
#define _IONBF 2

#define BUFSIZ 1024
#define FILENAME_MAX 4096
#define FOPEN_MAX 1000
#define TMP_MAX 10000
#define L_tmpnam 20

/* File access */
FILE *fopen(const char *, const char *);
FILE *freopen(const char *, const char *, FILE *);
int fclose(FILE *);

/* Buffering */
int setvbuf(FILE *, char *, int, size_t);
void setbuf(FILE *, char *);
int fflush(FILE *);

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
FILE *fdopen(int, const char *);
int fseeko(FILE *, off_t, int);
off_t ftello(FILE *);
int fileno(FILE *);
void flockfile(FILE *);
int ftrylockfile(FILE *);
void funlockfile(FILE *);
int getc_unlocked(FILE *);
int getchar_unlocked(void);
int putc_unlocked(int, FILE *);
int putchar_unlocked(int);
int dprintf(int, const char *, ...);
int vdprintf(int, const char *, va_list);
ssize_t getdelim(char **__restrict, size_t *__restrict, int, FILE *__restrict);
ssize_t getline(char **__restrict, size_t *__restrict, FILE *__restrict);
int renameat(int, const char *, int, const char *);
FILE *popen(const char *, const char *);
int pclose(FILE *);
FILE *open_memstream(char **, size_t *);
FILE *fmemopen(void *, size_t, const char *);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void setbuffer(FILE *, char *, size_t);
void setlinebuf(FILE *);
char *fgetln(FILE *, size_t *);
#endif

/* Direct I/O */
size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);

/* File positioning */
int fseek(FILE *, long, int);
long ftell(FILE *);
void rewind(FILE *);
int fgetpos(FILE *, fpos_t *);
int fsetpos(FILE *, const fpos_t *);

/* Error handling */
int feof(FILE *);
int ferror(FILE *);
void clearerr(FILE *);

/* Character I/O */
int fgetc(FILE *);
int getc(FILE *);
int getchar(void);
int fputc(int, FILE *);
int putc(int, FILE *);
int putchar(int);
int ungetc(int, FILE *);

/* Line I/O */
char *fgets(char *, int, FILE *);
#if __STDC_VERSION__ < 201112L
char *gets(char *);
#endif
int fputs(const char *, FILE *);
int puts(const char *);

/* Formatted output */
int printf(const char *, ...);
int fprintf(FILE *, const char *, ...);
int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...);
int vprintf(const char *, va_list);
int vfprintf(FILE *, const char *, va_list);
int vsprintf(char *, const char *, va_list);
int vsnprintf(char *, size_t, const char *, va_list);

/* Formatted input */
int scanf(const char *, ...);
int fscanf(FILE *, const char *, ...);
int sscanf(const char *, const char *, ...);
int vscanf(const char *, va_list);
int vfscanf(FILE *, const char *, va_list);
int vsscanf(const char *, const char *, va_list);

/* Line input */

/* File operations */
int remove(const char *);
int rename(const char *, const char *);

/* Temp files */
char *tmpnam(char *);
FILE *tmpfile(void);
/* Linux LP64 has one 64-bit file-offset model. Musl exposes tmpfile64
 * as a preprocessing alias rather than a distinct declaration. */
#if defined(_LARGEFILE64_SOURCE)
#define tmpfile64 tmpfile
#endif
/* POSIX.1-2024 removes these legacy names from the XSI namespace. */
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE) \
 || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE < 800)
#define P_tmpdir "/tmp"
char *tempnam(const char *, const char *);
#endif

/* Error */
void perror(const char *);

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define L_ctermid 20
char *ctermid(char *);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define L_cuserid 20
char *cuserid(char *);
#endif

/* GNU callback-backed streams */
#ifdef _GNU_SOURCE
typedef ssize_t (cookie_read_function_t)(void *, char *, size_t);
typedef ssize_t (cookie_write_function_t)(void *, const char *, size_t);
typedef int (cookie_seek_function_t)(void *, off_t *, int);
typedef int (cookie_close_function_t)(void *);

typedef struct _IO_cookie_io_functions_t {
    cookie_read_function_t *read;
    cookie_write_function_t *write;
    cookie_seek_function_t *seek;
    cookie_close_function_t *close;
} cookie_io_functions_t;

FILE *fopencookie(void *, const char *, cookie_io_functions_t);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int asprintf(char **__restrict, const char *__restrict, ...);
int vasprintf(char **__restrict, const char *__restrict, va_list);
#endif

#ifdef __cplusplus
}
#endif

#endif
