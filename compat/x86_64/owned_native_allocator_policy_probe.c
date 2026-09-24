/*
 * libc malloc-family policy across allocation size classes, against pinned
 * musl 1.2.6.
 *
 * The `memory.allocator-basic` and `memory.allocator-observability` probes
 * (libc_allocator_basic_runtime_v1_probe.c and
 * tests/fixtures/allocator_observability_test.c) fix each entry's argument,
 * errno and output rules at a few small sizes. This probe applies the same
 * rules across small, medium, large and huge blocks, where a native engine
 * takes different page paths:
 * - every entry, including zero-size requests, returns distinct, naturally
 *   (16-byte) aligned, freeable storage whose reported usable bytes are
 *   writable;
 * - calloc zeroes storage that a freed dirty block of the same class may
 *   supply, and rejects both overflowing factor orders with ENOMEM;
 * - realloc preserves contents across every class transition, keeps the
 *   original block intact on failure, and realloc(p, 0) returns freeable
 *   storage;
 * - aligned_alloc, posix_memalign and memalign honor large alignments, and
 *   posix_memalign leaves its output untouched on failure;
 * - successful allocation, reallocation, observation and free preserve errno,
 *   including a free from a thread other than the allocating one.
 * Only exact C outcomes are printed; usable sizes, which differ from
 * mallocng by design, are only checked against the request.
 */
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) fail(__LINE__); } while (0)

static void fail(int line)
{
    dprintf(2, "allocator policy line %d errno %d\n", line, errno);
    _exit(1);
}

static const size_t sizes[] = {
    0, 1, 8, 15, 16, 17, 24, 100, 1000, 1024, 4095, 4096, 4097, 10000,
    65535, 65536, 65537, 200000, 524288, 524289, (1u << 20) + 3,
    (4u << 20) - 16, 4u << 20, (8u << 20) + 5, 33u << 20,
};
#define SIZE_COUNT (sizeof sizes / sizeof *sizes)

static unsigned char pattern(size_t size, size_t index)
{
    return (unsigned char)(size * 7 + index * 13 + 1);
}

static void fill(unsigned char *block, size_t size)
{
    for (size_t i = 0; i < size; i++) block[i] = pattern(size, i);
}

static void intact(const unsigned char *block, size_t size, size_t length)
{
    for (size_t i = 0; i < length; i++) CHECK(block[i] == pattern(size, i));
}

/*
 * Natural alignment and errno preservation. Usable bytes beyond the request
 * are writable; the request's own bytes are left for the caller's checks.
 */
static void check_live(void *pointer, size_t request, int saved)
{
    CHECK(pointer && ((uintptr_t)pointer & 15) == 0 && errno == saved);
    size_t usable = malloc_usable_size(pointer);
    CHECK(usable >= request && errno == saved);
    if (usable > request) {
        unsigned char *bytes = pointer;
        bytes[request] = 0x5a;
        bytes[usable - 1] = 0xa5;
    }
}

static void size_classes(void)
{
    void *zero[8];
    for (int i = 0; i < 8; i++) {
        errno = EDOM;
        zero[i] = malloc(0);
        check_live(zero[i], 0, EDOM);
        for (int j = 0; j < i; j++) CHECK(zero[j] != zero[i]);
    }
    for (int i = 0; i < 8; i++) { errno = EDOM; free(zero[i]); CHECK(errno == EDOM); }

    for (size_t k = 0; k < SIZE_COUNT; k++) {
        size_t size = sizes[k];
        errno = ENOTTY;
        unsigned char *block = malloc(size);
        check_live(block, size, ENOTTY);
        fill(block, size);
        /* Dirty storage returned to the same class must come back zeroed. */
        free(block);
        CHECK(errno == ENOTTY);
        for (int round = 0; round < 3; round++) {
            unsigned char *zeroed = calloc(size ? size : 1, 1);
            check_live(zeroed, size, ENOTTY);
            for (size_t i = 0; i < size; i++) CHECK(zeroed[i] == 0);
            memset(zeroed, 0xee, size);
            free(zeroed);
        }
        unsigned char *product = calloc(3, size);
        check_live(product, 3 * size, ENOTTY);
        for (size_t i = 0; i < 3 * size; i++) CHECK(product[i] == 0);
        free(product);
        CHECK(errno == ENOTTY);
    }
    dprintf(1, "size classes: aligned, writable, zeroed, errno preserved\n");
}

static void overflow_and_failure(void)
{
    errno = 0;
    CHECK(calloc(SIZE_MAX / 2 + 1, 2) == 0 && errno == ENOMEM);
    errno = 0;
    CHECK(calloc(2, SIZE_MAX / 2 + 1) == 0 && errno == ENOMEM);
    errno = 0;
    CHECK(calloc((size_t)1 << 32, (size_t)1 << 32) == 0 && errno == ENOMEM);
    errno = 0;
    CHECK(malloc(SIZE_MAX - 4096) == 0 && errno == ENOMEM);
    errno = 0;
    CHECK(malloc(PTRDIFF_MAX) == 0 && errno == ENOMEM);

    for (size_t k = 0; k < SIZE_COUNT; k++) {
        size_t size = sizes[k];
        unsigned char *block = malloc(size);
        CHECK(block);
        fill(block, size);
        errno = 0;
        CHECK(realloc(block, PTRDIFF_MAX) == 0 && errno == ENOMEM);
        errno = 0;
        CHECK(reallocarray(block, SIZE_MAX / 4, 8) == 0 && errno == ENOMEM);
        intact(block, size, size);
        errno = EXDEV;
        CHECK(malloc_usable_size(block) >= size && errno == EXDEV);
        /* realloc(p, 0) returns freeable storage in musl. */
        block = realloc(block, 0);
        check_live(block, 0, EXDEV);
        free(block);
        CHECK(errno == EXDEV);
    }
    dprintf(1, "overflow and failed realloc keep the block and set ENOMEM\n");
}

static void realloc_transitions(void)
{
    /* Grow through every class, then shrink back, preserving the prefix. */
    size_t current = 1;
    unsigned char *block = malloc(current);
    CHECK(block);
    fill(block, current);
    for (size_t k = 0; k < SIZE_COUNT; k++) {
        size_t next = sizes[k] ? sizes[k] : 1;
        errno = EILSEQ;
        unsigned char *moved = realloc(block, next);
        check_live(moved, next, EILSEQ);
        size_t kept = current < next ? current : next;
        intact(moved, current, kept);
        block = moved;
        current = next;
        fill(block, current);
    }
    for (size_t k = SIZE_COUNT; k-- > 0;) {
        size_t next = sizes[k] ? sizes[k] : 1;
        errno = EILSEQ;
        unsigned char *moved = reallocarray(block, next, 1);
        check_live(moved, next, EILSEQ);
        intact(moved, current, current < next ? current : next);
        block = moved;
        current = next;
        fill(block, current);
    }
    free(block);
    dprintf(1, "realloc preserves contents across every class transition\n");
}

static void alignment(void)
{
    static const size_t alignments[] = { 16, 32, 64, 256, 4096, 16384, 65536, 1u << 20, 4u << 20 };
    static const size_t requests[] = { 0, 1, 100, 5000, 70000, 3u << 20 };
    for (size_t a = 0; a < sizeof alignments / sizeof *alignments; a++) {
        size_t align = alignments[a];
        for (size_t r = 0; r < sizeof requests / sizeof *requests; r++) {
            size_t size = requests[r];
            errno = ESRCH;
            unsigned char *block = aligned_alloc(align, size);
            check_live(block, size, ESRCH);
            CHECK(((uintptr_t)block & (align - 1)) == 0);
            free(block);
            void *output = (void *)(uintptr_t)1;
            CHECK(posix_memalign(&output, align, size) == 0 && errno == ESRCH);
            CHECK(((uintptr_t)output & (align - 1)) == 0);
            check_live(output, size, ESRCH);
            output = realloc(output, size + 4096);
            check_live(output, size + 4096, ESRCH);
            free(output);
            block = memalign(align, size);
            check_live(block, size, ESRCH);
            CHECK(((uintptr_t)block & (align - 1)) == 0);
            free(block);
            CHECK(errno == ESRCH);
        }
    }
    void *output = (void *)(uintptr_t)7;
    CHECK(posix_memalign(&output, 4096, PTRDIFF_MAX) == ENOMEM && output == (void *)(uintptr_t)7);
    CHECK(posix_memalign(&output, 48, 16) == EINVAL && output == (void *)(uintptr_t)7);
    CHECK(posix_memalign(&output, 4, 16) == EINVAL && output == (void *)(uintptr_t)7);
    errno = 0;
    CHECK(aligned_alloc(4096, SIZE_MAX - 100) == 0 && errno == ENOMEM);
    errno = 0;
    CHECK(memalign(4096 + 16, 10) == 0 && errno == EINVAL);
    errno = ESRCH;
    unsigned char *page = valloc(3u << 20);
    check_live(page, 3u << 20, ESRCH);
    CHECK(((uintptr_t)page & 4095) == 0);
    free(page);
    dprintf(1, "aligned entries honor large alignments and failure outputs\n");
}

/* Each block class is freed, grown and observed by the other thread. */
struct exchange { unsigned char *blocks[SIZE_COUNT]; int failure; };

static void *remote_worker(void *argument)
{
    struct exchange *exchange = argument;
    for (size_t k = 0; k < SIZE_COUNT; k++) {
        errno = EPERM;
        intact(exchange->blocks[k], sizes[k], sizes[k]);
        free(exchange->blocks[k]);
        if (errno != EPERM) { exchange->failure = 1; return 0; }
        exchange->blocks[k] = malloc(sizes[k] + 1);
        if (!exchange->blocks[k] || errno != EPERM) { exchange->failure = 2; return 0; }
        fill(exchange->blocks[k], sizes[k] + 1);
    }
    return 0;
}

static void remote_ownership(void)
{
    struct exchange exchange = { .failure = 0 };
    for (size_t k = 0; k < SIZE_COUNT; k++) {
        exchange.blocks[k] = malloc(sizes[k]);
        CHECK(exchange.blocks[k]);
        fill(exchange.blocks[k], sizes[k]);
    }
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, remote_worker, &exchange) == 0);
    CHECK(pthread_join(thread, 0) == 0 && exchange.failure == 0);
    for (size_t k = 0; k < SIZE_COUNT; k++) {
        size_t size = sizes[k] + 1;
        intact(exchange.blocks[k], size, size);
        errno = EPIPE;
        CHECK(malloc_usable_size(exchange.blocks[k]) >= size && errno == EPIPE);
        unsigned char *grown = realloc(exchange.blocks[k], 2 * size);
        check_live(grown, 2 * size, EPIPE);
        intact(grown, size, size);
        free(grown);
        CHECK(errno == EPIPE);
    }
    dprintf(1, "blocks of every class cross threads with errno preserved\n");
}

int main(void)
{
    size_classes();
    overflow_and_failure();
    realloc_transitions();
    alignment();
    remote_ownership();
    return 0;
}
