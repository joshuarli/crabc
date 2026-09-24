/*
 * Strong application allocator replacement against pinned musl 1.2.6.
 *
 * The executable defines its own allocator over a private arena. Its `free`,
 * `realloc` and `malloc_usable_size` reject any pointer outside that arena,
 * so a libc-owned (native) pointer handed to the application, or an
 * application pointer handed to libc's allocator, fails the run.
 *
 * `full` replaces malloc, free, calloc, realloc, aligned_alloc,
 * posix_memalign, memalign and malloc_usable_size. `trio` replaces only
 * malloc, free and realloc, the set musl requires; libc's calloc and
 * reallocarray must then allocate through the application's malloc/realloc.
 * Both scenarios exercise libc interfaces that return caller-owned storage
 * or grow a caller buffer, and libc interfaces whose storage libc owns.
 *
 * By default one image holds both the allocator and the client. For a
 * dynamic process the runner also builds the allocator alone
 * (-DOVERRIDE_PROVIDER_ONLY) as an initial DSO that preempts libc.so, and
 * the client alone (-DOVERRIDE_CLIENT_ONLY) as the executable.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <malloc.h>
#include <pthread.h>
#include <regex.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#define CHECK(c) do { if (!(c)) fail(__LINE__); } while (0)

static __attribute__((unused)) void fail(int line) {
    char text[64];
    int length = snprintf(text, sizeof text, "allocator override line %d errno %d\n", line, errno);
    (void)!write(2, text, (size_t)length);
    _exit(1);
}

/* The provider's arena ownership and call counters, visible to the client. */
int override_owned(const void *pointer);
extern unsigned long provider_calls, provider_frees;

#ifndef OVERRIDE_CLIENT_ONLY
/* A bump arena with a 32-byte header; freed blocks are poisoned, not reused. */
#define ARENA_SIZE (64u << 20)
static _Alignas(4096) unsigned char arena[ARENA_SIZE];
static size_t arena_used;
static pthread_mutex_t arena_lock = PTHREAD_MUTEX_INITIALIZER;
unsigned long provider_calls, provider_frees;
struct header { size_t size; size_t live; size_t magic; size_t pad; };
#define MAGIC ((size_t)0x6f76657272696465)

int override_owned(const void *pointer) {
    uintptr_t address = (uintptr_t)pointer;
    return address >= (uintptr_t)arena + sizeof(struct header)
        && address < (uintptr_t)arena + ARENA_SIZE;
}
static struct header *header_of(void *pointer) {
    if (!override_owned(pointer)) {
        static const char text[] = "allocator override: foreign pointer reached the application allocator\n";
        (void)!write(2, text, sizeof text - 1);
        _exit(3);
    }
    struct header *header = (struct header *)pointer - 1;
    if (header->magic != MAGIC || !header->live) {
        static const char text[] = "allocator override: invalid or double free\n";
        (void)!write(2, text, sizeof text - 1);
        _exit(4);
    }
    return header;
}
static void *arena_allocate(size_t alignment, size_t size) {
    if (alignment < 16) alignment = 16;
    if (size > ARENA_SIZE) { errno = ENOMEM; return 0; }
    pthread_mutex_lock(&arena_lock);
    size_t start = (arena_used + sizeof(struct header) + alignment - 1) & ~(alignment - 1);
    if (start + size > ARENA_SIZE) {
        pthread_mutex_unlock(&arena_lock);
        errno = ENOMEM;
        return 0;
    }
    arena_used = start + size;
    provider_calls++;
    pthread_mutex_unlock(&arena_lock);
    struct header *header = (struct header *)(arena + start) - 1;
    *header = (struct header){ size, 1, MAGIC, 0 };
    return arena + start;
}

void *malloc(size_t size) { return arena_allocate(16, size); }
void free(void *pointer) {
    if (!pointer) return;
    struct header *header = header_of(pointer);
    memset(pointer, 0x2a, header->size);
    header->live = 0;
    __atomic_add_fetch(&provider_frees, 1, __ATOMIC_RELAXED);
}
void *realloc(void *pointer, size_t size) {
    if (!pointer) return malloc(size);
    struct header *header = header_of(pointer);
    void *moved = malloc(size);
    if (!moved) return 0;
    memcpy(moved, pointer, header->size < size ? header->size : size);
    free(pointer);
    return moved;
}
#ifdef FULL_OVERRIDE
void *calloc(size_t count, size_t size) {
    if (size && count > SIZE_MAX / size) { errno = ENOMEM; return 0; }
    void *pointer = malloc(count * size);
    if (pointer) memset(pointer, 0, count * size);
    return pointer;
}
void *aligned_alloc(size_t alignment, size_t size) {
    if (alignment & (alignment - 1)) { errno = EINVAL; return 0; }
    return arena_allocate(alignment, size);
}
int posix_memalign(void **result, size_t alignment, size_t size) {
    if (alignment < sizeof(void *) || (alignment & (alignment - 1))) return EINVAL;
    void *pointer = arena_allocate(alignment, size);
    if (!pointer) return ENOMEM;
    *result = pointer;
    return 0;
}
void *memalign(size_t alignment, size_t size) { return aligned_alloc(alignment, size); }
size_t malloc_usable_size(void *pointer) { return pointer ? header_of(pointer)->size : 0; }
#endif
#endif

#ifndef OVERRIDE_PROVIDER_ONLY
#define owned override_owned

/* The application releases each caller-owned result itself. */
static void release_owned(void *pointer) { CHECK(owned(pointer)); free(pointer); }

static void caller_owned_results(void) {
    char *text = strdup("override");
    CHECK(text && !strcmp(text, "override"));
    release_owned(text);
    text = strndup("override", 4);
    CHECK(text && !strcmp(text, "over"));
    release_owned(text);
    CHECK(asprintf(&text, "%s-%d", "value", 42) == 8 && !strcmp(text, "value-42"));
    release_owned(text);
    wchar_t *wide = wcsdup(L"wide");
    CHECK(wide && !wcscmp(wide, L"wide"));
    release_owned(wide);
    char *resolved = realpath("/", 0);
    CHECK(resolved && !strcmp(resolved, "/"));
    release_owned(resolved);

    /* getline grows a caller-supplied application buffer through realloc. */
    static char input[] = "first line\nsecond, much longer line of input\n";
    FILE *stream = fmemopen(input, sizeof input - 1, "r");
    CHECK(stream);
    size_t capacity = 4;
    char *line = malloc(capacity);
    CHECK(getline(&line, &capacity, stream) == 11 && !strcmp(line, "first line\n"));
    CHECK(getline(&line, &capacity, stream) == 34 && owned(line));
    CHECK(fclose(stream) == 0);
    release_owned(line);

    char *buffer = 0;
    size_t length = 0;
    stream = open_memstream(&buffer, &length);
    CHECK(stream);
    for (int i = 0; i < 2000; i++) CHECK(fprintf(stream, "%04d", i) == 4);
    CHECK(fclose(stream) == 0);
    CHECK(length == 8000 && !memcmp(buffer, "0000", 4));
    release_owned(buffer);
    dprintf(1, "caller-owned results come from the application allocator\n");
}

static void derived_entries(void) {
    unsigned long before = provider_calls;
    unsigned char *zeroed = calloc(3, 100);
    CHECK(zeroed && owned(zeroed) && provider_calls > before);
    for (int i = 0; i < 300; i++) CHECK(zeroed[i] == 0);
    errno = 0;
    CHECK(calloc(SIZE_MAX / 2, 4) == 0 && errno == ENOMEM);
    unsigned char *array = reallocarray(zeroed, 10, 100);
    CHECK(array && owned(array));
    errno = 0;
    CHECK(reallocarray(array, SIZE_MAX / 2, 4) == 0 && errno == ENOMEM);
    release_owned(array);
    dprintf(1, "calloc and reallocarray use the application allocator\n");
}

static void *worker(void *argument) {
    char *text = strdup(argument);
    CHECK(text && owned(text));
    return text;
}

/* Interfaces whose storage libc owns internally must stay coherent. */
static void libc_owned_storage(void) {
    for (int i = 0; i < 40; i++) {
        FILE *stream = fopen("allocator-override.tmp", "w+");
        CHECK(stream);
        CHECK(fprintf(stream, "round %d\n", i) > 0 && fseek(stream, 0, SEEK_SET) == 0);
        char word[32];
        CHECK(fscanf(stream, "%31s", word) == 1 && !strcmp(word, "round"));
        CHECK(fclose(stream) == 0);
    }
    CHECK(remove("allocator-override.tmp") == 0);
    CHECK(setenv("CRABC_OVERRIDE", "one", 1) == 0 && setenv("CRABC_OVERRIDE", "two", 1) == 0);
    CHECK(!strcmp(getenv("CRABC_OVERRIDE"), "two") && unsetenv("CRABC_OVERRIDE") == 0);
    regex_t expression;
    CHECK(regcomp(&expression, "^(a|b)+c$", REG_EXTENDED) == 0);
    CHECK(regexec(&expression, "ababc", 0, 0, 0) == 0);
    regfree(&expression);
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) CHECK(pthread_create(&threads[i], 0, worker, "thread") == 0);
    for (int i = 0; i < 4; i++) {
        void *result;
        CHECK(pthread_join(threads[i], &result) == 0 && !strcmp(result, "thread"));
        release_owned(result);
    }
    dprintf(1, "libc-owned storage stays coherent\n");
}

#ifdef FULL_OVERRIDE
static void aligned_entries(void) {
    void *aligned = aligned_alloc(256, 1000);
    CHECK(aligned && owned(aligned) && ((uintptr_t)aligned & 255) == 0);
    CHECK(malloc_usable_size(aligned) >= 1000);
    release_owned(aligned);
    void *memaligned = 0;
    CHECK(posix_memalign(&memaligned, 64, 100) == 0 && owned(memaligned));
    release_owned(memaligned);
    memaligned = memalign(128, 50);
    CHECK(memaligned && owned(memaligned));
    release_owned(memaligned);
    dprintf(1, "aligned entries use the application allocator\n");
}
#endif

int main(void) {
    caller_owned_results();
    derived_entries();
#ifdef FULL_OVERRIDE
    aligned_entries();
#endif
    libc_owned_storage();
    CHECK(provider_frees > 0);
    return 0;
}
#endif
