/*
 * Complete public allocator-observability probe.
 *
 * The AArch64 crabc runtime, pinned-musl x86 reference, and private x86
 * candidate execute the same malloc_usable_size contract.  The x86 candidate
 * uses a raw single-threaded fork only as containment plumbing because public
 * x86 fork/atfork ownership is not selected by this capability.
 */

#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ || \
    (!defined(__x86_64__) && !defined(__aarch64__))
#error "allocator observability requires little-endian Linux LP64"
#endif

#ifdef CRABC_ALLOCATOR_OBSERVABILITY_CANDIDATE
#if !defined(__x86_64__)
#error "the private candidate fork shim is Linux/x86-64 only"
#endif
extern size_t __crabc_x86_allocator_observability_v1(void);
#endif

struct worker_result {
    void *pointer;
    size_t request;
    size_t usable;
    int failure;
};

static void *worker_main(void *opaque)
{
    struct worker_result *result = opaque;
    unsigned char *pointer;

    pointer = malloc(result->request);
    if (pointer == NULL) {
        result->failure = 1;
        return NULL;
    }
    pointer[0] = (unsigned char)result->request;
    pointer[result->request - 1] = (unsigned char)(result->request + 1);
    errno = EINTR;
    result->usable = malloc_usable_size(pointer);
    if (result->usable < result->request || errno != EINTR)
        result->failure = 2;
    result->pointer = pointer;
    return pointer;
}

static pid_t observability_fork(void)
{
#ifdef CRABC_ALLOCATOR_OBSERVABILITY_CANDIDATE
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(57L)
        : "rcx", "r11", "memory");
    if ((unsigned long)result >= (unsigned long)-4095L) {
        errno = (int)-result;
        return -1;
    }
    return (pid_t)result;
#else
    return fork();
#endif
}

int crabc_allocator_observability_probe(void)
{
    static const size_t requests[] = { 0, 1, 15, 16, 17, 4096, 262144 };
    struct worker_result workers[2] = {
        { NULL, 73, 0, 0 },
        { NULL, 65537, 0, 0 },
    };
    pthread_t threads[2];
    unsigned char *pointer;
    unsigned char *grown;
    void *aligned;
    pid_t child;
    int status;
    size_t index;
    size_t usable;

#ifdef CRABC_ALLOCATOR_OBSERVABILITY_CANDIDATE
    if (__crabc_x86_allocator_observability_v1() != 1)
        return 100;
#endif

    errno = EDOM;
    if (malloc_usable_size(NULL) != 0 || errno != EDOM)
        return 1;

    for (index = 0; index < sizeof(requests) / sizeof(requests[0]); ++index) {
        pointer = malloc(requests[index]);
        if (pointer == NULL)
            return 2;
        errno = E2BIG;
        usable = malloc_usable_size(pointer);
        if (usable < requests[index] ||
            malloc_usable_size(pointer) != usable || errno != E2BIG)
            return 3;
        if (requests[index] != 0) {
            pointer[0] = (unsigned char)index;
            pointer[requests[index] - 1] = (unsigned char)(index + 1);
        }
        free(pointer);
    }

    pointer = calloc(31, 7);
    if (pointer == NULL)
        return 4;
    errno = ECHILD;
    if (malloc_usable_size(pointer) < 31 * 7 || errno != ECHILD)
        return 4;
    for (index = 0; index < 31 * 7; ++index) {
        if (pointer[index] != 0)
            return 5;
    }
    free(pointer);

    aligned = aligned_alloc(256, 33);
    if (aligned == NULL || (uintptr_t)aligned % 256 != 0)
        return 6;
    errno = EAGAIN;
    if (malloc_usable_size(aligned) < 33 || errno != EAGAIN)
        return 6;
    free(aligned);

    pointer = malloc(4);
    if (pointer == NULL)
        return 7;
    pointer[0] = 1;
    pointer[1] = 2;
    pointer[2] = 3;
    pointer[3] = 4;
    grown = realloc(pointer, 8192);
    if (grown == NULL || grown[0] != 1 || grown[1] != 2 ||
        grown[2] != 3 || grown[3] != 4 ||
        malloc_usable_size(grown) < 8192)
        return 8;
    pointer = realloc(grown, 2);
    if (pointer == NULL || pointer[0] != 1 || pointer[1] != 2 ||
        malloc_usable_size(pointer) < 2)
        return 9;
    free(pointer);

    for (index = 0; index < 2; ++index) {
        if (pthread_create(&threads[index], NULL, worker_main, &workers[index]) != 0)
            return 10;
    }
    for (index = 0; index < 2; ++index) {
        void *joined = NULL;

        if (pthread_join(threads[index], &joined) != 0)
            return 11;
        if (joined != workers[index].pointer)
            return 18;
        if (workers[index].failure != 0)
            return 19 + workers[index].failure;
        errno = ENOENT;
        if (malloc_usable_size(workers[index].pointer) < workers[index].request ||
            malloc_usable_size(workers[index].pointer) != workers[index].usable ||
            errno != ENOENT)
            return 12;
        free(workers[index].pointer);
    }

    pointer = malloc(333);
    if (pointer == NULL)
        return 13;
    usable = malloc_usable_size(pointer);
    if (usable < 333)
        return 14;
    child = observability_fork();
    if (child < 0)
        return 15;
    if (child == 0) {
        void *child_pointer;

        errno = ERANGE;
        if (malloc_usable_size(pointer) != usable || errno != ERANGE)
            _exit(31);
        child_pointer = malloc(777);
        if (child_pointer == NULL)
            _exit(32);
        errno = ERANGE;
        if (malloc_usable_size(child_pointer) < 777 || errno != ERANGE)
            _exit(32);
        free(child_pointer);
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 16;
    errno = ENOTTY;
    if (malloc_usable_size(pointer) != usable || errno != ENOTTY)
        return 17;
    free(pointer);

    return 0;
}

int main(void)
{
    return crabc_allocator_observability_probe();
}
