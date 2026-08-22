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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "diagnostic_marker.h"
#include "pthread_create_join_tls_contract.h"
#include "pthread_mutex_cond_ping_pong_contract.h"
#include "pthread_mutex_uncontended_contract.h"
#include "tls_growth_contract.h"

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

static size_t parse_matrix_size(const char *text, size_t minimum)
{
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (text[0] == '\0' || end == NULL || *end != '\0'
        || value < minimum || value > 262144) {
        fprintf(stderr, "invalid scalar matrix size: %s\n", text);
        exit(2);
    }
    return (size_t)value;
}

static size_t parse_matrix_offset(const char *text)
{
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (text[0] == '\0' || end == NULL || *end != '\0' || value > 15) {
        fprintf(stderr, "invalid scalar matrix offset: %s\n", text);
        exit(2);
    }
    return (size_t)value;
}

static size_t parse_cache_span_size(const char *text)
{
    enum { CACHE_SPAN_BYTES = 128 * 1024 * 1024 };
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (text[0] == '\0' || end == NULL || *end != '\0' || value != CACHE_SPAN_BYTES) {
        fprintf(stderr, "invalid cache-spanning size: %s\n", text);
        exit(2);
    }
    return (size_t)value;
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

static void run_gettimeofday(unsigned long long iterations)
{
    struct timeval value;
    for (unsigned long long i = 0; i < iterations; ++i) {
        if (gettimeofday(&value, NULL) != 0 || value.tv_usec < 0 || value.tv_usec >= 1000000) {
            perror("gettimeofday");
            exit(3);
        }
        consume((uintptr_t)value.tv_sec + (uintptr_t)value.tv_usec);
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

static void run_fd_file(unsigned long long iterations, const char *path)
{
    unsigned char expected;
    unsigned char actual;
    struct stat status;

    for (unsigned long long i = 0; i < iterations; ++i) {
        const off_t offset = (off_t)(i & 4095U);
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            perror("open file fixture");
            exit(3);
        }
        if (fcntl(fd, F_GETFD) != FD_CLOEXEC || fstat(fd, &status) != 0 || status.st_size != 4096) {
            perror("file descriptor metadata");
            exit(3);
        }
        expected = (unsigned char)offset;
        if (pwrite(fd, &expected, 1, offset) != 1 || pread(fd, &actual, 1, offset) != 1 || actual != expected) {
            perror("file descriptor roundtrip");
            exit(3);
        }
        if (close(fd) != 0) {
            perror("close file fixture");
            exit(3);
        }
        consume((uintptr_t)actual + (uintptr_t)status.st_size);
    }
}

static void run_stdio_file(unsigned long long iterations, const char *path)
{
    enum { SIZE = 4096, SEEK_OFFSET = 1537 };
    unsigned char bytes[SIZE];

    for (unsigned long long i = 0; i < iterations; ++i) {
        FILE *stream = fopen(path, "r");
        if (stream == NULL) {
            perror("fopen file fixture");
            exit(3);
        }
        if (fread(bytes, 1, sizeof(bytes), stream) != sizeof(bytes)
            || bytes[0] != 0 || bytes[SIZE - 1] != 255) {
            perror("fread file fixture");
            exit(3);
        }
        if (fseek(stream, SEEK_OFFSET, SEEK_SET) != 0 || fgetc(stream) != 1
            || ungetc(1, stream) != 1 || fgetc(stream) != 1) {
            perror("buffered file positioning");
            exit(3);
        }
        if (fclose(stream) != 0) {
            perror("fclose file fixture");
            exit(3);
        }
        consume((uintptr_t)bytes[(unsigned int)i & (SIZE - 1)]);
    }
}

/*
 * A selected format/parse round trip on a lane-private file. Every operation
 * reconstructs its contents with `w+`, so no timed child observes data left
 * by a prior sample or by the other runtime lane. The direct Musl
 * differential fixture covers the same formatter/scanner grammar.
 */
static void run_stdio_format_parse(unsigned long long iterations, const char *path)
{
    for (unsigned long long i = 0; i < iterations; ++i) {
        const int expected_signed = (int)(i % 1024U) - 257;
        const unsigned int expected_unsigned = (unsigned int)i * 7U + 100U;
        const unsigned int expected_hex = (unsigned int)i + 0xf0U;
        const char *const expected_word = i & 1U ? "bravo" : "alpha";
        int signed_value = 0;
        unsigned int unsigned_value = 0;
        unsigned int hex_value = 0;
        char word[8] = {0};
        char formatted[16] = {0};
        int scan_signed = 0;
        int scan_tail = 0;
        char scan_word[8] = {0};
        FILE *stream = fopen(path, "w+");

        if (stream == NULL) {
            perror("fopen format/parse fixture");
            exit(3);
        }
        if (fprintf(stream, "%d %u %x %s tail", expected_signed, expected_unsigned,
                expected_hex, expected_word) <= 0
            || fflush(stream) != 0 || fseek(stream, 0, SEEK_SET) != 0) {
            perror("fprintf format/parse fixture");
            exit(3);
        }
        if (fscanf(stream, "%d %u %x %7s", &signed_value, &unsigned_value,
                &hex_value, word) != 4
            || signed_value != expected_signed || unsigned_value != expected_unsigned
            || hex_value != expected_hex || strcmp(word, expected_word) != 0) {
            perror("fscanf format/parse fixture");
            exit(3);
        }
        if (fgetc(stream) != ' ' || fgetc(stream) != 't' || fgetc(stream) != 'a'
            || fgetc(stream) != 'i' || fgetc(stream) != 'l') {
            perror("fscanf tail preservation");
            exit(3);
        }
        if (snprintf(formatted, sizeof(formatted), "%d+%d=%d", 1, 2, 3) != 5
            || strcmp(formatted, "1+2=3") != 0
            || sscanf("42 hello 99", "%d %7s %d", &scan_signed, scan_word,
                &scan_tail) != 3
            || scan_signed != 42 || scan_tail != 99 || strcmp(scan_word, "hello") != 0) {
            perror("memory format/parse fixture");
            exit(3);
        }
        if (fclose(stream) != 0) {
            perror("fclose format/parse fixture");
            exit(3);
        }
        consume((uintptr_t)(unsigned int)signed_value + unsigned_value + hex_value
            + (uintptr_t)formatted[0] + (uintptr_t)scan_word[0]);
    }
}

static void run_pthread_create_join_tls(unsigned long long iterations)
{
    pthread_key_t key;

    if (pthread_key_create(&key, NULL) != 0) {
        fprintf(stderr, "pthread key create failed\n");
        exit(3);
    }
    for (unsigned long long i = 0; i < iterations; ++i) {
        if (pthread_create_join_tls_round_run(key, (unsigned int)i) != 0) {
            fprintf(stderr, "pthread create/join TLS round failed\n");
            exit(3);
        }
        consume((uintptr_t)i);
    }
    if (pthread_key_delete(key) != 0) {
        fprintf(stderr, "pthread key delete failed\n");
        exit(3);
    }
}

static void run_pthread_mutex_uncontended(unsigned long long iterations)
{
    uint64_t observed = 0;

    if (pthread_mutex_uncontended_run(iterations, &observed) != 0) {
        fprintf(stderr, "pthread mutex uncontended contract failed\n");
        exit(3);
    }
    consume((uintptr_t)observed);
}

static void run_pthread_mutex_cond_ping_pong(unsigned long long iterations)
{
    uint64_t observed = 0;

    if (pthread_mutex_cond_ping_pong_run(iterations, &observed) != 0) {
        fprintf(stderr, "pthread mutex condition ping-pong contract failed\n");
        exit(3);
    }
    consume((uintptr_t)observed);
}

static void run_loader_dynamic_tls_growth(unsigned long long iterations, const char *directory)
{
    uint64_t observed = 0;

    if (iterations > TLS_GROWTH_MAX_MODULES
            || tls_growth_run(directory, (unsigned int)iterations, &observed) != 0) {
        fprintf(stderr, "dynamic TLS growth contract failed\n");
        exit(3);
    }
    consume((uintptr_t)observed);
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

enum { MATRIX_MAX_SIZE = 262144, MATRIX_STORAGE_SIZE = MATRIX_MAX_SIZE + 16 + 1 };

/*
 * The matrix rows name absolute pointer alignment, not merely an array offset.
 * Each backing array is explicitly 64-byte aligned; the runner supplies only
 * 0–15-byte offsets, so the aligned and unaligned rows are reproducible in
 * both staged runtime lanes.
 */
static unsigned char matrix_source[MATRIX_STORAGE_SIZE] __attribute__((aligned(64)));
static unsigned char matrix_destination[MATRIX_STORAGE_SIZE] __attribute__((aligned(64)));
static char matrix_text[MATRIX_STORAGE_SIZE] __attribute__((aligned(64)));
static const char matrix_needle[] = "needle";

static void run_memcpy_matrix(unsigned long long iterations, size_t size,
    size_t source_offset, size_t destination_offset)
{
    unsigned char *source = matrix_source + source_offset;
    unsigned char *destination = matrix_destination + destination_offset;

    memset(source, 0x5a, size);
    for (unsigned long long i = 0; i < iterations; ++i) {
        consume((uintptr_t)memcpy(destination, source, size));
        consume(destination[i % size]);
    }
}

static void run_memset_matrix(unsigned long long iterations, size_t size,
    size_t destination_offset)
{
    unsigned char *destination = matrix_destination + destination_offset;

    for (unsigned long long i = 0; i < iterations; ++i) {
        consume((uintptr_t)memset(destination, (int)i, size));
        consume(destination[i % size]);
    }
}

static void run_strlen_matrix(unsigned long long iterations, size_t size, size_t offset)
{
    char *text = matrix_text + offset;

    memset(text, 'a', size);
    text[size] = '\0';
    for (unsigned long long i = 0; i < iterations; ++i)
        consume(strlen(text));
}

static void run_memchr_matrix(unsigned long long iterations, size_t size, size_t offset)
{
    unsigned char *bytes = matrix_source + offset;

    memset(bytes, 'a', size);
    bytes[size - 1] = 'z';
    for (unsigned long long i = 0; i < iterations; ++i) {
        unsigned char *found = memchr(bytes, 'z', size);
        if (found != bytes + size - 1) {
            fprintf(stderr, "memchr scalar matrix result mismatch\n");
            exit(3);
        }
        consume((uintptr_t)found);
    }
}

static void prepare_matrix_search_text(size_t size, size_t offset)
{
    char *text = matrix_text + offset;

    memset(text, 'a', size);
    memcpy(text + size - (sizeof(matrix_needle) - 1), matrix_needle,
        sizeof(matrix_needle) - 1);
    text[size] = '\0';
}

static void run_strstr_matrix(unsigned long long iterations, size_t size, size_t offset)
{
    char *text = matrix_text + offset;
    char *expected = text + size - (sizeof(matrix_needle) - 1);

    prepare_matrix_search_text(size, offset);
    for (unsigned long long i = 0; i < iterations; ++i) {
        char *found = strstr(text, matrix_needle);
        if (found != expected) {
            fprintf(stderr, "strstr scalar matrix result mismatch\n");
            exit(3);
        }
        consume((uintptr_t)found);
    }
}

static void run_memmem_matrix(unsigned long long iterations, size_t size, size_t offset)
{
    unsigned char *bytes = matrix_source + offset;
    unsigned char *expected = bytes + size - (sizeof(matrix_needle) - 1);

    memset(bytes, 'a', size);
    memcpy(expected, matrix_needle, sizeof(matrix_needle) - 1);
    for (unsigned long long i = 0; i < iterations; ++i) {
        unsigned char *found = memmem(bytes, size, matrix_needle, sizeof(matrix_needle) - 1);
        if (found != expected) {
            fprintf(stderr, "memmem scalar matrix result mismatch\n");
            exit(3);
        }
        consume((uintptr_t)found);
    }
}

static unsigned char *map_span_file(const char *path, size_t bytes, int writable)
{
    struct stat status;
    int fd = open(path, writable ? O_RDWR | O_CLOEXEC : O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open cache-spanning fixture");
        exit(3);
    }
    if (fstat(fd, &status) != 0 || status.st_size < (off_t)bytes) {
        perror("cache-spanning fixture size");
        close(fd);
        exit(3);
    }
    void *mapping = mmap(NULL, bytes, PROT_READ | (writable ? PROT_WRITE : 0), MAP_PRIVATE, fd, 0);
    if (close(fd) != 0) {
        perror("close cache-spanning fixture");
        exit(3);
    }
    if (mapping == MAP_FAILED) {
        perror("mmap cache-spanning fixture");
        exit(3);
    }
    return mapping;
}

static void run_span_matrix(unsigned long long iterations, const char *primitive,
    size_t size, size_t offset, const char *source_path, const char *destination_path)
{
    enum { CACHE_SPAN_PADDING_BYTES = 16 };
    size_t mapping_bytes = offset + size + CACHE_SPAN_PADDING_BYTES;
    unsigned char *source_mapping = map_span_file(source_path, mapping_bytes, 0);
    unsigned char *destination_mapping = map_span_file(destination_path, mapping_bytes, 1);
    unsigned char *source = source_mapping + offset;
    unsigned char *destination = destination_mapping + offset;
    unsigned char *expected = source + size - (sizeof(matrix_needle) - 1);

    if (source[size] != '\0' || memcmp(expected, matrix_needle, sizeof(matrix_needle) - 1) != 0) {
        fprintf(stderr, "cache-spanning fixture content mismatch\n");
        exit(3);
    }
    if (strcmp(primitive, "memcpy") == 0) {
        for (unsigned long long i = 0; i < iterations; ++i) {
            void *result = memcpy(destination, source, size);
            if (result != destination || destination[0] != source[0] || destination[size - 1] != source[size - 1]) {
                fprintf(stderr, "cache-spanning memcpy result mismatch\n");
                exit(3);
            }
            consume((uintptr_t)result + destination[i & 1U]);
        }
    } else if (strcmp(primitive, "memset") == 0) {
        for (unsigned long long i = 0; i < iterations; ++i) {
            int value = (int)i;
            void *result = memset(destination, value, size);
            if (result != destination || destination[0] != (unsigned char)value
                || destination[size - 1] != (unsigned char)value) {
                fprintf(stderr, "cache-spanning memset result mismatch\n");
                exit(3);
            }
            consume((uintptr_t)result + destination[i & 1U]);
        }
    } else if (strcmp(primitive, "strlen") == 0) {
        for (unsigned long long i = 0; i < iterations; ++i) {
            size_t result = strlen((const char *)source);
            if (result != size) {
                fprintf(stderr, "cache-spanning strlen result mismatch\n");
                exit(3);
            }
            consume(result);
        }
    } else if (strcmp(primitive, "memchr") == 0) {
        for (unsigned long long i = 0; i < iterations; ++i) {
            void *result = memchr(source, 'z', size);
            if (result != NULL) {
                fprintf(stderr, "cache-spanning memchr result mismatch\n");
                exit(3);
            }
            consume((uintptr_t)result);
        }
    } else if (strcmp(primitive, "strstr") == 0) {
        for (unsigned long long i = 0; i < iterations; ++i) {
            char *result = strstr((const char *)source, matrix_needle);
            if (result != (char *)expected) {
                fprintf(stderr, "cache-spanning strstr result mismatch\n");
                exit(3);
            }
            consume((uintptr_t)result);
        }
    } else if (strcmp(primitive, "memmem") == 0) {
        for (unsigned long long i = 0; i < iterations; ++i) {
            void *result = memmem(source, size, matrix_needle, sizeof(matrix_needle) - 1);
            if (result != expected) {
                fprintf(stderr, "cache-spanning memmem result mismatch\n");
                exit(3);
            }
            consume((uintptr_t)result);
        }
    } else {
        fprintf(stderr, "unknown cache-spanning primitive: %s\n", primitive);
        exit(2);
    }
    if (munmap(destination_mapping, mapping_bytes) != 0 || munmap(source_mapping, mapping_bytes) != 0) {
        perror("munmap cache-spanning fixture");
        exit(3);
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

static void run_dlsym(unsigned long long iterations, const char *library, const char *symbol_name)
{
    void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        exit(3);
    }
    for (unsigned long long i = 0; i < iterations; ++i) {
        void *symbol = dlsym(handle, symbol_name);
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

static void run_dlopen_graph(const char *library)
{
    void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen graph: %s\n", dlerror());
        exit(3);
    }
    int (*value)(void) = (int (*)(void))dlsym(handle, "bench_graph_root_value");
    if (value == NULL || value() != 31) {
        fprintf(stderr, "graph value: %s\n", dlerror());
        exit(3);
    }
    if (dlclose(handle) != 0) {
        fprintf(stderr, "dlclose graph: %s\n", dlerror());
        exit(3);
    }
}

static void run_allocator_live(
    unsigned long long blocks,
    size_t size,
    int ready_fd,
    int continue_fd,
    int allocate_after_ready
)
{
    char continue_token;
    if (allocate_after_ready &&
        (write(ready_fd, "R", 1) != 1 || read(continue_fd, &continue_token, 1) != 1)) {
        perror("allocator-live synchronization");
        exit(3);
    }
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
    if (!allocate_after_ready &&
        (write(ready_fd, "R", 1) != 1 || read(continue_fd, &continue_token, 1) != 1)) {
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
    int marker_fd = diagnostic_marker_fd();

    if (marker_fd >= 0)
        write_diagnostic_marker(marker_fd, DIAGNOSTIC_MARKER_BEGIN, sizeof(DIAGNOSTIC_MARKER_BEGIN) - 1);

    if (strcmp(mode, "startup") == 0) {
        consume((uintptr_t)argv[0]);
    } else if (strcmp(mode, "clock_gettime") == 0) {
        run_clock(iterations);
    } else if (strcmp(mode, "gettimeofday") == 0) {
        run_gettimeofday(iterations);
    } else if (strcmp(mode, "getpid") == 0) {
        run_getpid(iterations);
    } else if (strcmp(mode, "open_close") == 0) {
        run_open_close(iterations);
    } else if (strcmp(mode, "fd_file_4k") == 0) {
        if (argc != 4) {
            fprintf(stderr, "fd_file_4k requires a fixture path\n");
            return 2;
        }
        run_fd_file(iterations, argv[3]);
    } else if (strcmp(mode, "stdio_file_4k") == 0) {
        if (argc != 4) {
            fprintf(stderr, "stdio_file_4k requires a fixture path\n");
            return 2;
        }
        run_stdio_file(iterations, argv[3]);
    } else if (strcmp(mode, "stdio_format_parse") == 0) {
        if (argc != 4) {
            fprintf(stderr, "stdio_format_parse requires a fixture path\n");
            return 2;
        }
        run_stdio_format_parse(iterations, argv[3]);
    } else if (strcmp(mode, "pthread_create_join_tls") == 0) {
        run_pthread_create_join_tls(iterations);
    } else if (strcmp(mode, "pthread_mutex_uncontended") == 0) {
        run_pthread_mutex_uncontended(iterations);
    } else if (strcmp(mode, "pthread_mutex_cond_ping_pong") == 0) {
        run_pthread_mutex_cond_ping_pong(iterations);
    } else if (strcmp(mode, "loader_dynamic_tls_growth") == 0) {
        if (argc != 4) {
            fprintf(stderr, "loader_dynamic_tls_growth requires a DSO directory\n");
            return 2;
        }
        run_loader_dynamic_tls_growth(iterations, argv[3]);
    } else if (strcmp(mode, "memcpy_16k") == 0) {
        run_memcpy(iterations);
    } else if (strcmp(mode, "memset_16k") == 0) {
        run_memset(iterations);
    } else if (strcmp(mode, "memcpy_matrix") == 0) {
        if (argc != 6) {
            fprintf(stderr, "memcpy_matrix requires size, source offset, and destination offset\n");
            return 2;
        }
        run_memcpy_matrix(iterations, parse_matrix_size(argv[3], 1),
            parse_matrix_offset(argv[4]), parse_matrix_offset(argv[5]));
    } else if (strcmp(mode, "memset_matrix") == 0) {
        if (argc != 5) {
            fprintf(stderr, "memset_matrix requires size and destination offset\n");
            return 2;
        }
        run_memset_matrix(iterations, parse_matrix_size(argv[3], 1), parse_matrix_offset(argv[4]));
    } else if (strcmp(mode, "strlen_matrix") == 0) {
        if (argc != 5) {
            fprintf(stderr, "strlen_matrix requires size and offset\n");
            return 2;
        }
        run_strlen_matrix(iterations, parse_matrix_size(argv[3], 1), parse_matrix_offset(argv[4]));
    } else if (strcmp(mode, "memchr_matrix") == 0) {
        if (argc != 5) {
            fprintf(stderr, "memchr_matrix requires size and offset\n");
            return 2;
        }
        run_memchr_matrix(iterations, parse_matrix_size(argv[3], 1), parse_matrix_offset(argv[4]));
    } else if (strcmp(mode, "strstr_matrix") == 0) {
        if (argc != 5) {
            fprintf(stderr, "strstr_matrix requires size and offset\n");
            return 2;
        }
        run_strstr_matrix(iterations,
            parse_matrix_size(argv[3], sizeof(matrix_needle) - 1), parse_matrix_offset(argv[4]));
    } else if (strcmp(mode, "memmem_matrix") == 0) {
        if (argc != 5) {
            fprintf(stderr, "memmem_matrix requires size and offset\n");
            return 2;
        }
        run_memmem_matrix(iterations,
            parse_matrix_size(argv[3], sizeof(matrix_needle) - 1), parse_matrix_offset(argv[4]));
    } else if (strcmp(mode, "span_matrix") == 0) {
        if (argc != 8) {
            fprintf(stderr, "span_matrix requires primitive, size, offset, source path, and destination path\n");
            return 2;
        }
        run_span_matrix(iterations, argv[3], parse_cache_span_size(argv[4]),
            parse_matrix_offset(argv[5]), argv[6], argv[7]);
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
    } else if (strcmp(mode, "dlsym_1") == 0 || strcmp(mode, "dlsym_128") == 0 || strcmp(mode, "dlsym_1024") == 0) {
        if (argc != 5) {
            fprintf(stderr, "%s requires a shared-library path and symbol name\n", mode);
            return 2;
        }
        run_dlsym(iterations, argv[3], argv[4]);
    } else if (strcmp(mode, "dlopen_graph") == 0) {
        if (iterations != 1 || argc != 4) {
            fprintf(stderr, "dlopen_graph requires one iteration and a root shared-library path\n");
            return 2;
        }
        run_dlopen_graph(argv[3]);
    } else if (strcmp(mode, "allocator_live") == 0) {
        if (argc != 6) {
            fprintf(stderr, "allocator_live requires SIZE READY_FD CONTINUE_FD\n");
            return 2;
        }
        run_allocator_live(iterations, (size_t)parse_count(argv[3], "size"),
            parse_fd(argv[4], "ready fd"), parse_fd(argv[5], "continue fd"), 0);
    } else if (strcmp(mode, "allocator_after_ready") == 0) {
        if (argc != 6) {
            fprintf(stderr, "allocator_after_ready requires SIZE READY_FD CONTINUE_FD\n");
            return 2;
        }
        run_allocator_live(iterations, (size_t)parse_count(argv[3], "size"),
            parse_fd(argv[4], "ready fd"), parse_fd(argv[5], "continue fd"), 1);
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }

    if (marker_fd >= 0)
        write_diagnostic_marker(marker_fd, DIAGNOSTIC_MARKER_END, sizeof(DIAGNOSTIC_MARKER_END) - 1);
    puts("ok");
    return 0;
}
