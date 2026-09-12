/*
 * Memory-only observer artifact for the frozen `fixtures/workload.c` program.
 * System declarations precede the source-local substitutions below so the
 * source is included byte-for-byte while only its selected call sites change.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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

#include "x86_64_memory_observer_protocol.h"

static int crabc_perf_memory_observer_clock_gettime(clockid_t clock_id,
    struct timespec *value);
static int crabc_perf_memory_observer_gettimeofday(struct timeval *value,
    void *timezone);
static pid_t crabc_perf_memory_observer_getpid(void);
static int crabc_perf_memory_observer_close(int descriptor);
static int crabc_perf_memory_observer_fclose(FILE *stream);
static void crabc_perf_memory_observer_free(void *pointer);
static int crabc_perf_memory_observer_munmap(void *address, size_t length);
static void *crabc_perf_memory_observer_dlopen(const char *path, int flags);
static int crabc_perf_memory_observer_dlclose(void *handle);
static int crabc_perf_memory_observer_pthread_create(pthread_t *thread,
    const pthread_attr_t *attributes, void *(*start_routine)(void *), void *argument);
static int crabc_perf_memory_observer_pthread_mutex_destroy(pthread_mutex_t *mutex);
static int crabc_perf_memory_observer_puts(const char *text);

#define main crabc_perf_memory_original_workload_main
#define clock_gettime crabc_perf_memory_observer_clock_gettime
#define gettimeofday crabc_perf_memory_observer_gettimeofday
#define getpid crabc_perf_memory_observer_getpid
#define close crabc_perf_memory_observer_close
#define fclose crabc_perf_memory_observer_fclose
#define free crabc_perf_memory_observer_free
#define munmap crabc_perf_memory_observer_munmap
#define dlopen crabc_perf_memory_observer_dlopen
#define dlclose crabc_perf_memory_observer_dlclose
#define pthread_create crabc_perf_memory_observer_pthread_create
#define pthread_mutex_destroy crabc_perf_memory_observer_pthread_mutex_destroy
#define puts crabc_perf_memory_observer_puts
#include "fixtures/workload.c"
#undef puts
#undef pthread_mutex_destroy
#undef pthread_create
#undef dlclose
#undef dlopen
#undef munmap
#undef free
#undef fclose
#undef close
#undef getpid
#undef gettimeofday
#undef clock_gettime
#undef main

static int
crabc_perf_memory_observer_clock_gettime(clockid_t clock_id, struct timespec *value)
{
    int result = clock_gettime(clock_id, value);
    int call_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_CLOCK) &&
        ++crabc_perf_memory_observer.clock_calls == crabc_perf_memory_observer.iterations &&
        result == 0 && value != NULL && value->tv_nsec >= 0 && value->tv_nsec < 1000000000L)
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_CLOCK_FINAL_CALL);
    errno = call_errno;
    return result;
}

static int
crabc_perf_memory_observer_gettimeofday(struct timeval *value, void *timezone)
{
    int result = gettimeofday(value, timezone);
    int call_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_CLOCK) &&
        ++crabc_perf_memory_observer.clock_calls == crabc_perf_memory_observer.iterations &&
        result == 0 && value != NULL && value->tv_usec >= 0 && value->tv_usec < 1000000)
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_CLOCK_FINAL_CALL);
    errno = call_errno;
    return result;
}

static pid_t
crabc_perf_memory_observer_getpid(void)
{
    pid_t result = getpid();
    int call_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_CLOCK) &&
        ++crabc_perf_memory_observer.clock_calls == crabc_perf_memory_observer.iterations &&
        result > 0)
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_CLOCK_FINAL_CALL);
    errno = call_errno;
    return result;
}

static int
crabc_perf_memory_observer_close(int descriptor)
{
    int saved_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_OPEN) &&
        ++crabc_perf_memory_observer.close_calls == crabc_perf_memory_observer.iterations)
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_OPEN_BEFORE_CLOSE);
    else if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_FD) &&
        ++crabc_perf_memory_observer.close_calls == crabc_perf_memory_observer.iterations)
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_FD_BEFORE_CLOSE);
    errno = saved_errno;
    return close(descriptor);
}

static int
crabc_perf_memory_observer_fclose(FILE *stream)
{
    int saved_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_STDIO) &&
        ++crabc_perf_memory_observer.fclose_calls == crabc_perf_memory_observer.iterations)
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_STDIO_BEFORE_FCLOSE);
    errno = saved_errno;
    return fclose(stream);
}

static void
crabc_perf_memory_observer_free(void *pointer)
{
    int saved_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_ALLOCATOR) &&
        ++crabc_perf_memory_observer.free_calls == crabc_perf_memory_observer.iterations)
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_ALLOCATOR_BEFORE_FINAL_FREE);
    errno = saved_errno;
    free(pointer);
}

static int
crabc_perf_memory_observer_munmap(void *address, size_t length)
{
    int saved_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_SPAN) &&
        !crabc_perf_memory_observer.first_munmap_seen) {
        crabc_perf_memory_observer.first_munmap_seen = 1;
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_SPAN_BEFORE_FIRST_MUNMAP);
    }
    errno = saved_errno;
    return munmap(address, length);
}

static void *
crabc_perf_memory_observer_dlopen(const char *path, int flags)
{
    void *handle = dlopen(path, flags);
    int call_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_TLS_GROWTH) && handle != NULL &&
        crabc_perf_memory_observer.tls_loads < crabc_perf_memory_observer.iterations) {
        enum crabc_perf_memory_phase phase = (enum crabc_perf_memory_phase)(
            CRABC_PERF_MEMORY_TLS_PARENT_LOAD_0 + crabc_perf_memory_observer.tls_loads);

        (void)crabc_perf_memory_checkpoint(phase);
        crabc_perf_memory_observer.tls_loads++;
    }
    errno = call_errno;
    return handle;
}

static int
crabc_perf_memory_observer_dlclose(void *handle)
{
    int saved_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_DLSYM))
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_DLSYM_BEFORE_DLCLOSE);
    else if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_GRAPH))
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_GRAPH_BEFORE_DLCLOSE);
    errno = saved_errno;
    return dlclose(handle);
}

enum { CRABC_PERF_MEMORY_THREAD_SLOTS = 2 };

struct crabc_perf_memory_thread_slot {
    int active;
    void *(*original_start)(void *);
    void *argument;
    enum crabc_perf_memory_phase phase;
};

static struct crabc_perf_memory_thread_slot
    crabc_perf_memory_thread_slots[CRABC_PERF_MEMORY_THREAD_SLOTS];
static unsigned long long crabc_perf_memory_thread_creates;

static int
crabc_perf_memory_thread_phase(enum crabc_perf_memory_phase *phase)
{
    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_PTHREAD_CREATE_JOIN_TLS) &&
        crabc_perf_memory_thread_creates + 1 == crabc_perf_memory_observer.iterations) {
        *phase = CRABC_PERF_MEMORY_PTHREAD_CALLBACK_READY;
        return 1;
    }
    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_MUTEX_COND_PING_PONG) &&
        crabc_perf_memory_thread_creates == 0) {
        *phase = CRABC_PERF_MEMORY_PINGPONG_BEFORE_WORKER_EXIT;
        return 1;
    }
    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_TLS_GROWTH) &&
        crabc_perf_memory_thread_creates == 0) {
        *phase = CRABC_PERF_MEMORY_TLS_WORKER_COMPLETE;
        return 1;
    }
    return 0;
}

static void *
crabc_perf_memory_thread_trampoline(void *opaque)
{
    struct crabc_perf_memory_thread_slot *slot = opaque;
    void *result = slot->original_start(slot->argument);
    int call_errno = errno;

    (void)crabc_perf_memory_checkpoint(slot->phase);
    errno = call_errno;
    slot->active = 0;
    return result;
}

static int
crabc_perf_memory_observer_pthread_create(pthread_t *thread,
    const pthread_attr_t *attributes, void *(*start_routine)(void *), void *argument)
{
    enum crabc_perf_memory_phase phase;
    struct crabc_perf_memory_thread_slot *slot = NULL;
    int needs_trampoline = crabc_perf_memory_thread_phase(&phase);
    int result;
    int call_errno;

    if (!needs_trampoline) {
        result = pthread_create(thread, attributes, start_routine, argument);
        call_errno = errno;
        if (result == 0 && crabc_perf_memory_is_row(
                CRABC_PERF_MEMORY_ROW_PTHREAD_CREATE_JOIN_TLS))
            crabc_perf_memory_thread_creates++;
        errno = call_errno;
        return result;
    }
    for (size_t index = 0; index < CRABC_PERF_MEMORY_THREAD_SLOTS; index++) {
        if (!crabc_perf_memory_thread_slots[index].active) {
            slot = &crabc_perf_memory_thread_slots[index];
            break;
        }
    }
    if (slot == NULL)
        return EAGAIN;
    slot->active = 1;
    slot->original_start = start_routine;
    slot->argument = argument;
    slot->phase = phase;
    result = pthread_create(thread, attributes, crabc_perf_memory_thread_trampoline, slot);
    call_errno = errno;
    if (result == 0)
        crabc_perf_memory_thread_creates++;
    else
        slot->active = 0;
    errno = call_errno;
    return result;
}

static int
crabc_perf_memory_observer_pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    int saved_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_MUTEX_UNCONTENDED))
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_MUTEX_BEFORE_DESTROY);
    errno = saved_errno;
    return pthread_mutex_destroy(mutex);
}

static int
crabc_perf_memory_observer_puts(const char *text)
{
    int saved_errno = errno;

    if (crabc_perf_memory_is_row(CRABC_PERF_MEMORY_ROW_SCALAR) && text != NULL &&
        strcmp(text, "ok") == 0)
        (void)crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_SCALAR_ARRAYS_LIVE);
    errno = saved_errno;
    return puts(text);
}

int
main(int argc, char **argv)
{
    int begun = crabc_perf_memory_begin_workload(argc, argv);
    int status;

    if (begun == -1)
        return 2;
    if (begun == -2)
        return 1;
    status = crabc_perf_memory_original_workload_main(argc, argv);
    return crabc_perf_memory_finish(status);
}
