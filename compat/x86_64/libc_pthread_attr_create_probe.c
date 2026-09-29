/* Same-source static pthread attribute consumption through a real worker.
 * Each case uses only initialized records and a selected single-worker route.
 * The published trace contains stable statuses and observations, never TIDs
 * or randomized stack addresses.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>

_Static_assert(sizeof(pthread_attr_t) == 56, "musl pthread attribute ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_create),
    int (*)(pthread_t *__restrict, const pthread_attr_t *__restrict,
        void *(*)(void *), void *__restrict)), "pthread_create declaration");

static _Alignas(4096) unsigned char caller_stack[65536];
static volatile int detached_entered;
static volatile int detached_release;
static volatile int detached_done;

static void trace(const char *text, unsigned long count)
{
    register long number __asm__("rax") = 1;
    register long descriptor __asm__("rdi") = 1;
    register const char *buffer __asm__("rsi") = text;
    register unsigned long length __asm__("rdx") = count;
    __asm__ volatile("syscall" : "+a"(number) : "D"(descriptor),
        "S"(buffer), "d"(length) : "rcx", "r11", "memory");
}

#define TRACE(literal) trace(literal, sizeof(literal) - 1)

struct worker_result {
    uintptr_t frame;
    int *errno_address;
};

static void *observe_stack(void *opaque)
{
    struct worker_result *result = opaque;
    volatile unsigned char frame = 0;
    result->frame = (uintptr_t)&frame;
    result->errno_address = __errno_location();
    return opaque;
}

static void *hold_detached(void *opaque)
{
    (void)opaque;
    __atomic_store_n(&detached_entered, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&detached_release, __ATOMIC_ACQUIRE) == 0)
        ;
    __atomic_store_n(&detached_done, 1, __ATOMIC_RELEASE);
    return 0;
}

int crabc_x86_64_pthread_attr_create_probe(void)
{
    pthread_attr_t attr;
    pthread_t thread;
    struct sched_param parameter = { .sched_priority = INT_MIN };
    struct worker_result result = { 0, 0 };
    void *joined = 0;
    int main_errno = E2BIG;

    errno = main_errno;
    if (pthread_attr_init(&attr) != 0 ||
        pthread_attr_setstacksize(&attr, 65536) != 0 ||
        pthread_attr_setguardsize(&attr, 4096) != 0 ||
        pthread_attr_setschedpolicy(&attr, -7) != 0 ||
        pthread_attr_setschedparam(&attr, &parameter) != 0)
        return 10;
    /* Inherited scheduling must ignore even deliberately unusable metadata. */
    if (pthread_create(&thread, &attr, observe_stack, &result) != 0)
        return 11;
    if (pthread_join(thread, &joined) != 0 || joined != &result ||
        result.frame == 0 || result.errno_address == __errno_location() ||
        errno != main_errno)
        return 12;
    if (pthread_attr_destroy(&attr) != 0)
        return 13;
    TRACE("mapped-stack/inherited-scheduler ok\n");

    if (pthread_attr_init(&attr) != 0 ||
        pthread_attr_setstack(&attr, caller_stack, sizeof(caller_stack)) != 0)
        return 20;
    result.frame = 0;
    result.errno_address = 0;
    if (pthread_create(&thread, &attr, observe_stack, &result) != 0)
        return 21;
    if (pthread_join(thread, &joined) != 0 || joined != &result ||
        result.frame < (uintptr_t)caller_stack ||
        result.frame >= (uintptr_t)(caller_stack + sizeof(caller_stack)) ||
        errno != main_errno)
        return 22;
    if (pthread_attr_destroy(&attr) != 0)
        return 23;
    TRACE("caller-stack-frame ok\n");

    if (pthread_attr_init(&attr) != 0 ||
        pthread_attr_setstack(&attr, caller_stack, sizeof(caller_stack)) != 0 ||
        pthread_attr_setstacksize(&attr, sizeof(caller_stack)) != 0)
        return 24;
    result.frame = 0;
    if (pthread_create(&thread, &attr, observe_stack, &result) != 0)
        return 25;
    if (pthread_join(thread, &joined) != 0 || joined != &result ||
        result.frame == 0 ||
        (result.frame >= (uintptr_t)caller_stack &&
         result.frame < (uintptr_t)(caller_stack + sizeof(caller_stack))) ||
        errno != main_errno)
        return 26;
    if (pthread_attr_destroy(&attr) != 0)
        return 27;
    TRACE("stacksize-clears-caller-stack ok\n");

    if (pthread_attr_init(&attr) != 0 ||
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0)
        return 30;
    if (pthread_create(&thread, &attr, hold_detached, 0) != 0)
        return 31;
    while (__atomic_load_n(&detached_entered, __ATOMIC_ACQUIRE) == 0)
        ;
    __atomic_store_n(&detached_release, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&detached_done, __ATOMIC_ACQUIRE) == 0)
        ;
    if (errno != main_errno || pthread_attr_destroy(&attr) != 0)
        return 32;
    TRACE("detached-at-create/start ok\n");
    return 0;
}

#ifndef CRABC_PTHREAD_ATTR_CREATE_FREESTANDING
int main(void) { return crabc_x86_64_pthread_attr_create_probe(); }
#endif
