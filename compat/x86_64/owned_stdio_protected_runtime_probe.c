/* Exercise shared stdio collision, handle lookup, and body callability. */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "stdio-protected-runtime:%d errno=%d\n", __LINE__, errno); \
        return 1; \
    } \
} while (0)

/* These strong main-image spellings must not become libc's protected bodies. */
int __uflow(FILE *stream)
{
    (void)stream;
    return -101;
}

int __overflow(FILE *stream, int byte)
{
    (void)stream;
    (void)byte;
    return -102;
}

static ssize_t cookie_write(void *opaque, const char *source, size_t count)
{
    size_t *writes = opaque;

    (void)source;
    *writes += count;
    return (ssize_t)count;
}

int main(void)
{
    typedef int (*uflow_fn)(FILE *);
    typedef int (*overflow_fn)(FILE *, int);
    char input[] = "q";
    cookie_io_functions_t functions = { .write = cookie_write };
    void *handle;
    void *resolved_uflow;
    void *resolved_overflow;
    uflow_fn library_uflow;
    overflow_fn library_overflow;
    FILE *stream;
    size_t writes = 0;

    handle = dlopen("libc.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(handle != NULL);
    resolved_uflow = dlsym(handle, "__uflow");
    resolved_overflow = dlsym(handle, "__overflow");
    CHECK(resolved_uflow != NULL && resolved_overflow != NULL);
    CHECK((uintptr_t)resolved_uflow != (uintptr_t)__uflow);
    CHECK((uintptr_t)resolved_overflow != (uintptr_t)__overflow);
    library_uflow = (uflow_fn)resolved_uflow;
    library_overflow = (overflow_fn)resolved_overflow;

    stream = fmemopen(input, 1, "r");
    CHECK(stream != NULL);
    CHECK(library_uflow(stream) == 'q');
    CHECK(fclose(stream) == 0);

    stream = fopencookie(&writes, "w", functions);
    CHECK(stream != NULL);
    CHECK(setvbuf(stream, NULL, _IONBF, 0) == 0);
    CHECK(library_overflow(stream, 'z') == 'z' && writes == 1);
    CHECK(fclose(stream) == 0);
    CHECK(dlclose(handle) == 0);
    puts("owned-stdio-protected-runtime-ok");
    return 0;
}
