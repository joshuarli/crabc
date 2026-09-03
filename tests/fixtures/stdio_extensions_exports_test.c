#define _GNU_SOURCE 1

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int asprintf(char **, const char *, ...);
extern int vasprintf(char **, const char *, va_list);

extern void _flushlbf(void);
extern int __fsetlocking(FILE *, int);
extern int __fwriting(FILE *);
extern int __freading(FILE *);
extern int __freadable(FILE *);
extern int __fwritable(FILE *);
extern int __flbf(FILE *);
extern size_t __fbufsize(FILE *);
extern size_t __fpending(FILE *);
extern int __fpurge(FILE *);
extern int fpurge(FILE *);
extern size_t __freadahead(FILE *);
extern const char *__freadptr(FILE *, size_t *);
extern void __freadptrinc(FILE *, size_t);
extern void __fseterr(FILE *);

static int call_vasprintf(char **out, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int result = vasprintf(out, fmt, args);
    va_end(args);
    return result;
}

static int test_formatted_allocation(void) {
    char *out = NULL;
    int n = asprintf(&out, "value=%d %s", 42, "answer");
    if (n != 15 || !out || strcmp(out, "value=42 answer") != 0) return 1;
    free(out);

    out = NULL;
    n = call_vasprintf(&out, "%s:%d", "vas", 7);
    if (n != 5 || !out || strcmp(out, "vas:7") != 0) return 2;
    free(out);
    return 0;
}

static int test_stdio_ext(void) {
    char storage[32] = {0};
    FILE *stream = fmemopen(storage, sizeof storage, "w+");
    if (!stream) return 1;
    if (__fbufsize(stream) != BUFSIZ) return 2;
    if (__fsetlocking(stream, 0) != 0) return 3;
    if (!__freadable(stream) || !__fwritable(stream)) return 4;
    if (__flbf(stream) || __freading(stream) || __fwriting(stream)) return 5;
    if (fileno_unlocked(stream) != -1) return 6;
    if (fwrite_unlocked("abc", 1, 3, stream) != 3) return 7;
    if (!__fwriting(stream) || __freading(stream)) return 8;
    if (__fpending(stream) != 3) return 9;
    if (fflush_unlocked(stream) != 0) return 10;
    if (__fpending(stream) != 0 || strcmp(storage, "abc") != 0) return 11;

    rewind(stream);
    char read_buf[4] = {0};
    if (fread_unlocked(read_buf, 1, 3, stream) != 3 || memcmp(read_buf, "abc", 3) != 0) return 12;
    rewind(stream);
    if (fgetc(stream) != 'a') return 13;
    size_t ahead = 0;
    const char *read_ptr = __freadptr(stream, &ahead);
    if (!__freading(stream) || __freadahead(stream) != 2 || !read_ptr || ahead != 2) return 14;
    if (*read_ptr != 'b') return 15;
    __freadptrinc(stream, 1);
    if (fgetc(stream) != 'c' || __freadahead(stream) != 0) return 16;
    if (__freadptr(stream, &ahead) != NULL) return 17;
    __fseterr(stream);
    if (!ferror(stream)) return 18;
    clearerr(stream);
    if (ferror(stream)) return 19;

    if (fwrite_unlocked("discard", 1, 7, stream) != 7) return 20;
    if (fpurge(stream) != 0 || __fpending(stream) != 0) return 21;
    if (storage[3] != '\0') return 22;
    if (__fpurge(stream) != 0) return 23;
    fclose(stream);
    _flushlbf();
    return 0;
}

static int test_read_mode_capabilities(void) {
    const char path[] = "/tmp/crabc-c-abi-stdio-read-mode";
    FILE *stream = fopen(path, "w");
    if (!stream) return 1;
    if (fputs("input", stream) < 0 || fclose(stream) != 0) return 2;

    stream = fopen(path, "r");
    if (!stream) return 3;
    if (!__freadable(stream) || __fwritable(stream)) return 4;
    if (fclose(stream) != 0 || remove(path) != 0) return 5;
    return 0;
}

static int test_fread_preserves_pending_input(void) {
    char storage[] = "abcdef";
    char bytes[5] = {0};
    FILE *stream = fmemopen(storage, sizeof storage - 1, "r");
    if (!stream) return 1;
    if (fgetc(stream) != 'a' || ungetc('a', stream) != 'a') return 2;
    if (fread(bytes, 1, 4, stream) != 4 || memcmp(bytes, "abcd", 4) != 0) return 3;
    if (fgetc(stream) != 'e' || fclose(stream) != 0) return 4;
    return 0;
}

int main(void) {
    int result = test_formatted_allocation();
    if (result) return result;
    result = test_stdio_ext();
    if (result) return result + 20;
    result = test_read_mode_capabilities();
    if (result) return result + 50;
    result = test_fread_preserves_pending_input();
    if (result) return result + 60;
    puts("c-abi stdio extensions ok");
    return 0;
}
