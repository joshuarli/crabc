/*
 * Comparable dynamic-libc workloads.
 *
 * This program is compiled exactly once with the pinned musl toolchain.  The
 * measurement runner changes only PT_INTERP and the library directory, so the
 * musl and crabc lanes execute the same application code and inputs.  It does
 * not time itself: the Python parent uses wait4(2) for isolated CPU/resource
 * accounting and a monotonic parent clock for elapsed time.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile uintptr_t sink;

static unsigned long long parse_count(const char *text, const char *name)
{
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (text[0] == '\0' || end == NULL || *end != '\0' || value == 0) {
        fprintf(stderr, "invalid %s: %s\n", name, text);
        exit(2);
    }
    return value;
}

static int parse_fd(const char *text, const char *name)
{
    unsigned long long value = parse_count(text, name);
    if (value > 0x7fffffffU) {
        fprintf(stderr, "invalid %s: %s\n", name, text);
        exit(2);
    }
    return (int)value;
}

static void consume(uintptr_t value)
{
    sink ^= value + (uintptr_t)0x9e3779b9U;
}

static void run_clock(unsigned long long iterations)
{
    struct timespec value;
    for (unsigned long long i = 0; i < iterations; ++i) {
        if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
            perror("clock_gettime");
            exit(3);
        }
        consume((uintptr_t)value.tv_nsec);
    }
}

static void run_getpid(unsigned long long iterations)
{
    for (unsigned long long i = 0; i < iterations; ++i)
        consume((uintptr_t)getpid());
}

static void run_open_close(unsigned long long iterations)
{
    for (unsigned long long i = 0; i < iterations; ++i) {
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            perror("open /dev/null");
            exit(3);
        }
        if (close(fd) != 0) {
            perror("close /dev/null");
            exit(3);
        }
        consume((uintptr_t)fd);
    }
}

static void run_memcpy(unsigned long long iterations)
{
    enum { SIZE = 16384 };
    static unsigned char source[SIZE];
    static unsigned char destination[SIZE];
    memset(source, 0x5a, sizeof(source));
    for (unsigned long long i = 0; i < iterations; ++i) {
        consume((uintptr_t)memcpy(destination, source, sizeof(source)));
        consume(destination[(unsigned int)i & (SIZE - 1)]);
    }
}

static void run_memset(unsigned long long iterations)
{
    enum { SIZE = 16384 };
    static unsigned char destination[SIZE];
    for (unsigned long long i = 0; i < iterations; ++i) {
        consume((uintptr_t)memset(destination, (int)i, sizeof(destination)));
        consume(destination[(unsigned int)i & (SIZE - 1)]);
    }
}

static void run_strlen(unsigned long long iterations)
{
    enum { SIZE = 16384 };
    static char text[SIZE];
    memset(text, 'a', sizeof(text));
    text[SIZE - 1] = '\0';
    for (unsigned long long i = 0; i < iterations; ++i)
        consume(strlen(text));
}

static void run_memchr(unsigned long long iterations)
{
    enum { SIZE = 16384 };
    static unsigned char text[SIZE];
    memset(text, 'a', sizeof(text));
    text[SIZE - 1] = 'z';
    for (unsigned long long i = 0; i < iterations; ++i)
        consume((uintptr_t)memchr(text, 'z', sizeof(text)));
}

static void run_strstr(unsigned long long iterations)
{
    enum { SIZE = 4096 };
    static char text[SIZE];
    const char needle[] = "needle-at-the-end";
    memset(text, 'a', sizeof(text));
    memcpy(text + SIZE - sizeof(needle), needle, sizeof(needle));
    for (unsigned long long i = 0; i < iterations; ++i)
        consume((uintptr_t)strstr(text, needle));
}

static void run_memmem(unsigned long long iterations)
{
    enum { SIZE = 4096 };
    static unsigned char text[SIZE];
    static const unsigned char needle[] = "needle-at-the-end";
    memset(text, 'a', sizeof(text));
    memcpy(text + SIZE - sizeof(needle), needle, sizeof(needle));
    for (unsigned long long i = 0; i < iterations; ++i)
        consume((uintptr_t)memmem(text, sizeof(text), needle, sizeof(needle) - 1));
}

static void run_allocator(unsigned long long iterations, size_t size)
{
    for (unsigned long long i = 0; i < iterations; ++i) {
        unsigned char *allocation = malloc(size);
        if (allocation == NULL) {
            perror("malloc");
            exit(3);
        }
        allocation[0] = (unsigned char)i;
        allocation[size - 1] = (unsigned char)(i >> 8);
        consume(allocation[0] + allocation[size - 1]);
        free(allocation);
    }
}

static void run_dlsym(unsigned long long iterations, const char *library)
{
    void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        exit(3);
    }
    for (unsigned long long i = 0; i < iterations; ++i) {
        void *symbol = dlsym(handle, "bench_symbol_7f");
        if (symbol == NULL) {
            fprintf(stderr, "dlsym: %s\n", dlerror());
            exit(3);
        }
        consume((uintptr_t)symbol);
    }
    if (dlclose(handle) != 0) {
        fprintf(stderr, "dlclose: %s\n", dlerror());
        exit(3);
    }
}

static void run_allocator_live(unsigned long long blocks, size_t size, int ready_fd, int continue_fd)
{
    char continue_token;
    unsigned char **allocations = calloc((size_t)blocks, sizeof(*allocations));
    if (allocations == NULL) {
        perror("calloc pointers");
        exit(3);
    }
    for (unsigned long long i = 0; i < blocks; ++i) {
        allocations[i] = malloc(size);
        if (allocations[i] == NULL) {
            perror("malloc live");
            exit(3);
        }
        memset(allocations[i], (int)i, size);
        consume(allocations[i][size - 1]);
    }
    if (write(ready_fd, "R", 1) != 1 || read(continue_fd, &continue_token, 1) != 1) {
        perror("allocator-live synchronization");
        exit(3);
    }
    for (unsigned long long i = 0; i < blocks; ++i)
        free(allocations[i]);
    free(allocations);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s MODE ITERATIONS [ARGUMENTS]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    unsigned long long iterations = parse_count(argv[2], "iterations");

    if (strcmp(mode, "startup") == 0) {
        consume((uintptr_t)argv[0]);
    } else if (strcmp(mode, "clock_gettime") == 0) {
        run_clock(iterations);
    } else if (strcmp(mode, "getpid") == 0) {
        run_getpid(iterations);
    } else if (strcmp(mode, "open_close") == 0) {
        run_open_close(iterations);
    } else if (strcmp(mode, "memcpy_16k") == 0) {
        run_memcpy(iterations);
    } else if (strcmp(mode, "memset_16k") == 0) {
        run_memset(iterations);
    } else if (strcmp(mode, "strlen_16k") == 0) {
        run_strlen(iterations);
    } else if (strcmp(mode, "memchr_16k") == 0) {
        run_memchr(iterations);
    } else if (strcmp(mode, "strstr_4k") == 0) {
        run_strstr(iterations);
    } else if (strcmp(mode, "memmem_4k") == 0) {
        run_memmem(iterations);
    } else if (strcmp(mode, "allocator_64") == 0) {
        run_allocator(iterations, 64);
    } else if (strcmp(mode, "allocator_4k") == 0) {
        run_allocator(iterations, 4096);
    } else if (strcmp(mode, "dlsym_128") == 0) {
        if (argc != 4) {
            fprintf(stderr, "dlsym_128 requires a shared-library path\n");
            return 2;
        }
        run_dlsym(iterations, argv[3]);
    } else if (strcmp(mode, "allocator_live") == 0) {
        if (argc != 6) {
            fprintf(stderr, "allocator_live requires SIZE READY_FD CONTINUE_FD\n");
            return 2;
        }
        run_allocator_live(iterations, (size_t)parse_count(argv[3], "size"),
            parse_fd(argv[4], "ready fd"), parse_fd(argv[5], "continue fd"));
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }

    puts("ok");
    return 0;
}
