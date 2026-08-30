/* Static crabc-libc x86-64 pthread read/write-lock fixture.
 *
 * The same project-header C body first runs with pinned musl 1.2.6, then as
 * a `-nostdlib -static` executable linked only through the selected crabc
 * archive.  It proves the complete rwlock/attribute family as one coherent
 * pthread/TLS artifact: exact x86 object layouts, private and process-shared
 * initialization, reader/writer exclusion, simultaneous readers, timed
 * status rules, wake-before-deadline handoff, and a cross-process shared
 * futex wake.  Fixture-local raw syscalls only provide time, mapping, fork,
 * wait, and exit plumbing; they do not select a C process runtime, CRT,
 * loader, or public x86 support.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 && sizeof(int) == 4,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(pthread_rwlock_t) == 56 && _Alignof(pthread_rwlock_t) == 8,
    "musl x86 pthread_rwlock_t layout");
_Static_assert(sizeof(pthread_rwlockattr_t) == 8 &&
    _Alignof(pthread_rwlockattr_t) == 4,
    "musl x86 pthread_rwlockattr_t layout");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "musl x86 timespec layout");
_Static_assert(SYS_mmap == 9 && SYS_munmap == 11 && SYS_fork == 57 &&
    SYS_exit == 60 && SYS_wait4 == 61 && SYS_clock_gettime == 228,
    "x86 rwlock fixture syscall numbers");
_Static_assert(PTHREAD_PROCESS_PRIVATE == 0 && PTHREAD_PROCESS_SHARED == 1,
    "musl rwlock pshared values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_init),
    int (*)(pthread_rwlock_t *__restrict, const pthread_rwlockattr_t *__restrict)),
    "pthread_rwlock_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_destroy),
    int (*)(pthread_rwlock_t *)), "pthread_rwlock_destroy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_rdlock),
    int (*)(pthread_rwlock_t *)), "pthread_rwlock_rdlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_tryrdlock),
    int (*)(pthread_rwlock_t *)), "pthread_rwlock_tryrdlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_timedrdlock),
    int (*)(pthread_rwlock_t *__restrict, const struct timespec *__restrict)),
    "pthread_rwlock_timedrdlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_wrlock),
    int (*)(pthread_rwlock_t *)), "pthread_rwlock_wrlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_trywrlock),
    int (*)(pthread_rwlock_t *)), "pthread_rwlock_trywrlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_timedwrlock),
    int (*)(pthread_rwlock_t *__restrict, const struct timespec *__restrict)),
    "pthread_rwlock_timedwrlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_unlock),
    int (*)(pthread_rwlock_t *)), "pthread_rwlock_unlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlockattr_init),
    int (*)(pthread_rwlockattr_t *)), "pthread_rwlockattr_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlockattr_destroy),
    int (*)(pthread_rwlockattr_t *)), "pthread_rwlockattr_destroy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlockattr_setpshared),
    int (*)(pthread_rwlockattr_t *, int)),
    "pthread_rwlockattr_setpshared declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlockattr_getpshared),
    int (*)(const pthread_rwlockattr_t *, int *)),
    "pthread_rwlockattr_getpshared declaration");

enum {
    FUTEX_WAITER_BIT = (int)0x80000000U,
    FIXTURE_TIMEOUT_SECONDS = 3,
    TIMED_FUTEX_TIMEOUT_SECONDS = 1,
    CONTENTION_ROUNDS = 3,
    READER_WORKER_COUNT = 2,
    SHARED_MAPPING_BYTES = 4096,
};

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long argument_one)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one) : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long argument_one, long argument_two)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument_one, long argument_two,
    long argument_three, long argument_four)
{
    long result;
    register long register_four __asm__("r10") = argument_four;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(register_four)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall6(long number, long argument_one, long argument_two,
    long argument_three, long argument_four, long argument_five,
    long argument_six)
{
    long result;
    register long register_four __asm__("r10") = argument_four;
    register long register_five __asm__("r8") = argument_five;
    register long register_six __asm__("r9") = argument_six;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(register_four), "r"(register_five),
          "r"(register_six)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_failed(long result)
{
    return result < 0 && result >= -4095;
}

static void raw_exit(int status) __attribute__((noreturn));

static void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    for (;;)
        __asm__ volatile("pause" ::: "memory");
}

static int raw_clock(clockid_t clock, struct timespec *output)
{
    return raw_syscall2(SYS_clock_gettime, clock, (long)(void *)output) == 0
        ? 0 : -1;
}

static int deadline_after(clockid_t clock, struct timespec *output, long seconds)
{
    if (raw_clock(clock, output) != 0)
        return -1;
    output->tv_sec += seconds;
    return 0;
}

static int deadline_reached(clockid_t clock, const struct timespec *deadline)
{
    struct timespec now;

    if (raw_clock(clock, &now) != 0)
        return 1;
    return now.tv_sec > deadline->tv_sec ||
        (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec);
}

/* Bounded atomic polling keeps the fixture independent of an extra condition
 * object while rejecting an implementation that never publishes its futex
 * waiter mark. */
static int wait_for_int(const volatile int *value, int expected)
{
    struct timespec deadline;

    if (deadline_after(CLOCK_MONOTONIC, &deadline, FIXTURE_TIMEOUT_SECONDS) != 0)
        return -1;
    do {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) == expected)
            return 0;
    } while (!deadline_reached(CLOCK_MONOTONIC, &deadline));
    return -1;
}

static int wait_for_nonnegative_count(const volatile int *value, int expected)
{
    struct timespec deadline;

    if (deadline_after(CLOCK_MONOTONIC, &deadline, FIXTURE_TIMEOUT_SECONDS) != 0)
        return -1;
    do {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) >= expected)
            return 0;
    } while (!deadline_reached(CLOCK_MONOTONIC, &deadline));
    return -1;
}

static int wait_for_waiter_mark(const volatile int *lock_word)
{
    struct timespec deadline;

    if (deadline_after(CLOCK_MONOTONIC, &deadline, FIXTURE_TIMEOUT_SECONDS) != 0)
        return -1;
    do {
        if ((__atomic_load_n(lock_word, __ATOMIC_ACQUIRE) & FUTEX_WAITER_BIT) != 0)
            return 0;
    } while (!deadline_reached(CLOCK_MONOTONIC, &deadline));
    return -1;
}

/* This initializer is deliberately distinct from the initialized local
 * records below: it proves the project header's all-zero static shape is the
 * exact state machine used by the selected x86 archive. */
static pthread_rwlock_t static_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static int run_static_initializer_probe(void)
{
    if (pthread_rwlock_rdlock(&static_rwlock) != 0)
        return 1;
    if (pthread_rwlock_tryrdlock(&static_rwlock) != 0)
        return 2;
    if (pthread_rwlock_trywrlock(&static_rwlock) != EBUSY)
        return 3;
    if (pthread_rwlock_unlock(&static_rwlock) != 0 ||
        pthread_rwlock_unlock(&static_rwlock) != 0)
        return 4;
    if (pthread_rwlock_wrlock(&static_rwlock) != 0)
        return 5;
    if (pthread_rwlock_tryrdlock(&static_rwlock) != EBUSY ||
        pthread_rwlock_trywrlock(&static_rwlock) != EBUSY)
        return 6;
    if (pthread_rwlock_unlock(&static_rwlock) != 0)
        return 7;
    return pthread_rwlock_destroy(&static_rwlock) == 0 ? 0 : 8;
}

static int run_attribute_and_private_probe(void)
{
    pthread_rwlockattr_t attribute;
    pthread_rwlock_t rwlock;
    int process_shared = -1;

    errno = E2BIG;
    if (pthread_rwlockattr_init(&attribute) != 0)
        return 1;
    if (pthread_rwlockattr_getpshared(&attribute, &process_shared) != 0 ||
        process_shared != PTHREAD_PROCESS_PRIVATE)
        return 2;
    if (pthread_rwlockattr_setpshared(&attribute, PTHREAD_PROCESS_SHARED) != 0)
        return 3;
    if (pthread_rwlockattr_setpshared(&attribute, -1) != EINVAL ||
        pthread_rwlockattr_getpshared(&attribute, &process_shared) != 0 ||
        process_shared != PTHREAD_PROCESS_SHARED)
        return 4;
    if (pthread_rwlockattr_setpshared(&attribute, 2) != EINVAL ||
        pthread_rwlockattr_getpshared(&attribute, &process_shared) != 0 ||
        process_shared != PTHREAD_PROCESS_SHARED)
        return 5;
    if (pthread_rwlockattr_destroy(&attribute) != 0)
        return 6;

    if (pthread_rwlock_init(&rwlock, 0) != 0)
        return 7;
    if (pthread_rwlock_rdlock(&rwlock) != 0 ||
        pthread_rwlock_tryrdlock(&rwlock) != 0 ||
        pthread_rwlock_trywrlock(&rwlock) != EBUSY)
        return 8;
    if (pthread_rwlock_unlock(&rwlock) != 0 ||
        pthread_rwlock_unlock(&rwlock) != 0)
        return 9;
    if (pthread_rwlock_trywrlock(&rwlock) != 0 ||
        pthread_rwlock_tryrdlock(&rwlock) != EBUSY ||
        pthread_rwlock_unlock(&rwlock) != 0)
        return 10;
    if (pthread_rwlock_destroy(&rwlock) != 0)
        return 11;
    return errno == E2BIG ? 0 : 12;
}

static int run_timed_status_probe(void)
{
    pthread_rwlock_t rwlock;
    struct timespec past;
    struct timespec invalid_negative = { .tv_sec = 1, .tv_nsec = -1 };
    struct timespec invalid_large = { .tv_sec = 1, .tv_nsec = 1000000000L };

    errno = E2BIG;
    if (deadline_after(CLOCK_REALTIME, &past, -1) != 0)
        return 1;
    if (pthread_rwlock_init(&rwlock, 0) != 0)
        return 2;
    if (pthread_rwlock_wrlock(&rwlock) != 0)
        return 3;
    if (pthread_rwlock_timedrdlock(&rwlock, &past) != ETIMEDOUT)
        return 4;
    if (pthread_rwlock_timedrdlock(&rwlock, &invalid_negative) != EINVAL ||
        pthread_rwlock_timedrdlock(&rwlock, &invalid_large) != EINVAL)
        return 5;
    if (pthread_rwlock_unlock(&rwlock) != 0)
        return 6;
    if (pthread_rwlock_rdlock(&rwlock) != 0)
        return 7;
    if (pthread_rwlock_timedwrlock(&rwlock, &past) != ETIMEDOUT)
        return 8;
    if (pthread_rwlock_timedwrlock(&rwlock, &invalid_negative) != EINVAL ||
        pthread_rwlock_timedwrlock(&rwlock, &invalid_large) != EINVAL)
        return 9;
    if (pthread_rwlock_unlock(&rwlock) != 0)
        return 10;

    /* Musl tries first: an invalid absolute deadline must not reject an
     * uncontended acquisition. */
    if (pthread_rwlock_timedrdlock(&rwlock, &invalid_negative) != 0 ||
        pthread_rwlock_unlock(&rwlock) != 0)
        return 11;
    if (pthread_rwlock_timedwrlock(&rwlock, &invalid_large) != 0 ||
        pthread_rwlock_unlock(&rwlock) != 0)
        return 12;
    if (pthread_rwlock_destroy(&rwlock) != 0)
        return 13;
    return errno == E2BIG ? 0 : 14;
}

struct timed_reader_round {
    pthread_rwlock_t rwlock;
    volatile int entered;
    volatile int acquired;
    int lock_result;
    int unlock_result;
    int final_errno;
};

static void *timed_reader_main(void *opaque)
{
    struct timed_reader_round *round = opaque;
    struct timespec deadline;

    errno = EACCES;
    round->lock_result = -1;
    round->unlock_result = -1;
    __atomic_store_n(&round->entered, 1, __ATOMIC_RELEASE);
    if (deadline_after(CLOCK_REALTIME, &deadline, FIXTURE_TIMEOUT_SECONDS) == 0)
        round->lock_result = pthread_rwlock_timedrdlock(&round->rwlock, &deadline);
    if (round->lock_result == 0) {
        __atomic_store_n(&round->acquired, 1, __ATOMIC_RELEASE);
        round->unlock_result = pthread_rwlock_unlock(&round->rwlock);
    }
    round->final_errno = errno;
    return (void *)(uintptr_t)0x102030405060708ULL;
}

static int run_timed_release_probe(void)
{
    struct timed_reader_round round = { 0 };
    pthread_t thread;
    void *result = 0;
    int status = 0;

    errno = E2BIG;
    if (pthread_rwlock_init(&round.rwlock, 0) != 0)
        return 1;
    if (pthread_rwlock_wrlock(&round.rwlock) != 0) {
        (void)pthread_rwlock_destroy(&round.rwlock);
        return 2;
    }
    if (pthread_create(&thread, 0, timed_reader_main, &round) != 0) {
        (void)pthread_rwlock_unlock(&round.rwlock);
        (void)pthread_rwlock_destroy(&round.rwlock);
        return 3;
    }
    if (wait_for_int(&round.entered, 1) != 0 ||
        wait_for_waiter_mark((volatile int *)&round.rwlock.__u.__i[0]) != 0)
        status = 4;
    if (pthread_rwlock_unlock(&round.rwlock) != 0 && status == 0)
        status = 5;
    if (pthread_join(thread, &result) != 0 && status == 0)
        status = 6;
    if (status == 0 && (result != (void *)(uintptr_t)0x102030405060708ULL ||
        round.lock_result != 0 || round.unlock_result != 0 ||
        __atomic_load_n(&round.acquired, __ATOMIC_ACQUIRE) != 1 ||
        round.final_errno != EACCES))
        status = 7;
    if (pthread_rwlock_destroy(&round.rwlock) != 0 && status == 0)
        status = 8;
    if (errno != E2BIG && status == 0)
        status = 9;
    return status;
}

struct timed_timeout_round {
    pthread_rwlock_t rwlock;
    volatile int entered;
    int child_reads;
    int lock_result;
    int final_errno;
};

static void *timed_timeout_main(void *opaque)
{
    struct timed_timeout_round *round = opaque;
    struct timespec deadline;

    errno = EACCES;
    round->lock_result = -1;
    __atomic_store_n(&round->entered, 1, __ATOMIC_RELEASE);
    if (deadline_after(CLOCK_REALTIME, &deadline,
            TIMED_FUTEX_TIMEOUT_SECONDS) == 0) {
        round->lock_result = round->child_reads
            ? pthread_rwlock_timedrdlock(&round->rwlock, &deadline)
            : pthread_rwlock_timedwrlock(&round->rwlock, &deadline);
    }
    round->final_errno = errno;
    return (void *)(uintptr_t)0x5566778899aabbccULL;
}

/* Keep the incompatible parent hold through join.  The observed waiter mark
 * and a future realtime deadline force the selected timed operation through
 * its actual FUTEX_WAIT route before ETIMEDOUT, rather than only testing the
 * immediate already-expired-deadline status path. */
static int run_timed_futex_timeout_case(int parent_holds_writer)
{
    struct timed_timeout_round round = {
        .child_reads = parent_holds_writer,
        .lock_result = -1,
        .final_errno = -1,
    };
    pthread_t thread;
    void *result = 0;
    int status = 0;

    errno = E2BIG;
    if (pthread_rwlock_init(&round.rwlock, 0) != 0)
        return 1;
    if ((parent_holds_writer ? pthread_rwlock_wrlock(&round.rwlock) :
        pthread_rwlock_rdlock(&round.rwlock)) != 0) {
        (void)pthread_rwlock_destroy(&round.rwlock);
        return 2;
    }
    if (pthread_create(&thread, 0, timed_timeout_main, &round) != 0) {
        (void)pthread_rwlock_unlock(&round.rwlock);
        (void)pthread_rwlock_destroy(&round.rwlock);
        return 3;
    }
    if (wait_for_int(&round.entered, 1) != 0 ||
        wait_for_waiter_mark((volatile int *)&round.rwlock.__u.__i[0]) != 0)
        status = 4;
    if (pthread_join(thread, &result) != 0 && status == 0)
        status = 5;
    if (status == 0 &&
        (result != (void *)(uintptr_t)0x5566778899aabbccULL ||
        round.lock_result != ETIMEDOUT || round.final_errno != EACCES))
        status = 6;
    if (pthread_rwlock_unlock(&round.rwlock) != 0 && status == 0)
        status = 7;
    if (pthread_rwlock_destroy(&round.rwlock) != 0 && status == 0)
        status = 8;
    if (errno != E2BIG && status == 0)
        status = 9;
    return status;
}

struct reader_group {
    pthread_rwlock_t rwlock;
    volatile int entered;
    volatile int acquired;
    volatile int active_readers;
    volatile int maximum_readers;
    volatile int release_readers;
    volatile int overlap;
};

struct reader_worker {
    struct reader_group *group;
    int lock_result;
    int unlock_result;
    int final_errno;
    uintptr_t marker;
};

static void *reader_worker_main(void *opaque)
{
    struct reader_worker *worker = opaque;
    struct reader_group *group = worker->group;
    int active;

    errno = EACCES;
    worker->lock_result = -1;
    worker->unlock_result = -1;
    __atomic_fetch_add(&group->entered, 1, __ATOMIC_RELEASE);
    worker->lock_result = pthread_rwlock_rdlock(&group->rwlock);
    if (worker->lock_result == 0) {
        active = __atomic_add_fetch(&group->active_readers, 1, __ATOMIC_ACQ_REL);
        if (active > __atomic_load_n(&group->maximum_readers, __ATOMIC_ACQUIRE))
            __atomic_store_n(&group->maximum_readers, active, __ATOMIC_RELEASE);
        if (active > READER_WORKER_COUNT)
            __atomic_store_n(&group->overlap, 1, __ATOMIC_RELEASE);
        __atomic_fetch_add(&group->acquired, 1, __ATOMIC_RELEASE);
        while (__atomic_load_n(&group->release_readers, __ATOMIC_ACQUIRE) == 0)
            ;
        __atomic_fetch_sub(&group->active_readers, 1, __ATOMIC_RELEASE);
        worker->unlock_result = pthread_rwlock_unlock(&group->rwlock);
    }
    worker->final_errno = errno;
    return (void *)worker->marker;
}

static int run_reader_concurrency_round(void)
{
    struct reader_group group = { 0 };
    struct reader_worker workers[READER_WORKER_COUNT] = {
        { .group = &group, .lock_result = -1, .unlock_result = -1,
          .final_errno = -1, .marker = (uintptr_t)0x1122334455667788ULL },
        { .group = &group, .lock_result = -1, .unlock_result = -1,
          .final_errno = -1, .marker = (uintptr_t)0x8877665544332211ULL },
    };
    pthread_t threads[READER_WORKER_COUNT];
    void *results[READER_WORKER_COUNT] = { 0, 0 };
    int created = 0;
    int index;
    int status = 0;

    errno = E2BIG;
    if (pthread_rwlock_init(&group.rwlock, 0) != 0)
        return 1;
    if (pthread_rwlock_wrlock(&group.rwlock) != 0) {
        (void)pthread_rwlock_destroy(&group.rwlock);
        return 2;
    }
    for (index = 0; index != READER_WORKER_COUNT; ++index) {
        if (pthread_create(&threads[index], 0, reader_worker_main, &workers[index]) != 0) {
            status = 3 + index;
            break;
        }
        ++created;
    }
    if (created != 0 && wait_for_int(&group.entered, created) != 0 && status == 0)
        status = 6;
    if (created != 0 && wait_for_waiter_mark((volatile int *)&group.rwlock.__u.__i[0]) != 0 && status == 0)
        status = 7;
    if (pthread_rwlock_unlock(&group.rwlock) != 0 && status == 0)
        status = 8;
    if (created == READER_WORKER_COUNT &&
        wait_for_int(&group.acquired, READER_WORKER_COUNT) != 0 && status == 0)
        status = 9;
    __atomic_store_n(&group.release_readers, 1, __ATOMIC_RELEASE);
    for (index = 0; index != created; ++index) {
        if (pthread_join(threads[index], &results[index]) != 0 && status == 0)
            status = 10 + index;
    }
    if (status == 0 && (created != READER_WORKER_COUNT ||
        results[0] != (void *)workers[0].marker ||
        results[1] != (void *)workers[1].marker ||
        workers[0].lock_result != 0 || workers[1].lock_result != 0 ||
        workers[0].unlock_result != 0 || workers[1].unlock_result != 0 ||
        workers[0].final_errno != EACCES || workers[1].final_errno != EACCES ||
        __atomic_load_n(&group.maximum_readers, __ATOMIC_ACQUIRE) != READER_WORKER_COUNT ||
        __atomic_load_n(&group.active_readers, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&group.overlap, __ATOMIC_ACQUIRE) != 0))
        status = 13;
    if (pthread_rwlock_destroy(&group.rwlock) != 0 && status == 0)
        status = 14;
    if (errno != E2BIG && status == 0)
        status = 15;
    return status;
}

struct writer_round {
    pthread_rwlock_t rwlock;
    volatile int entered;
    volatile int acquired;
    volatile int release_writer;
    int lock_result;
    int unlock_result;
    int final_errno;
};

static void *writer_worker_main(void *opaque)
{
    struct writer_round *round = opaque;

    errno = EACCES;
    round->lock_result = -1;
    round->unlock_result = -1;
    __atomic_store_n(&round->entered, 1, __ATOMIC_RELEASE);
    round->lock_result = pthread_rwlock_wrlock(&round->rwlock);
    if (round->lock_result == 0) {
        __atomic_store_n(&round->acquired, 1, __ATOMIC_RELEASE);
        while (__atomic_load_n(&round->release_writer, __ATOMIC_ACQUIRE) == 0)
            ;
        round->unlock_result = pthread_rwlock_unlock(&round->rwlock);
    }
    round->final_errno = errno;
    return (void *)(uintptr_t)0x99aabbccddeeff00ULL;
}

static int run_writer_exclusion_round(void)
{
    struct writer_round round = { 0 };
    pthread_t thread;
    void *result = 0;
    int status = 0;

    errno = E2BIG;
    if (pthread_rwlock_init(&round.rwlock, 0) != 0)
        return 1;
    if (pthread_rwlock_rdlock(&round.rwlock) != 0) {
        (void)pthread_rwlock_destroy(&round.rwlock);
        return 2;
    }
    if (pthread_create(&thread, 0, writer_worker_main, &round) != 0) {
        (void)pthread_rwlock_unlock(&round.rwlock);
        (void)pthread_rwlock_destroy(&round.rwlock);
        return 3;
    }
    if (wait_for_int(&round.entered, 1) != 0 ||
        wait_for_waiter_mark((volatile int *)&round.rwlock.__u.__i[0]) != 0)
        status = 4;
    /* The writer must still be blocked while the parent reader hold remains
     * live.  Check that fact before release; a post-unlock bookkeeping flag
     * would race a correct awakened writer and turn scheduling into a false
     * overlap report. */
    if (__atomic_load_n(&round.acquired, __ATOMIC_ACQUIRE) != 0 && status == 0)
        status = 5;
    if (pthread_rwlock_unlock(&round.rwlock) != 0 && status == 0)
        status = 6;
    if (wait_for_int(&round.acquired, 1) != 0 && status == 0)
        status = 7;
    __atomic_store_n(&round.release_writer, 1, __ATOMIC_RELEASE);
    if (pthread_join(thread, &result) != 0 && status == 0)
        status = 8;
    if (status == 0 && (result != (void *)(uintptr_t)0x99aabbccddeeff00ULL ||
        round.lock_result != 0 || round.unlock_result != 0 ||
        round.final_errno != EACCES))
        status = 9;
    if (pthread_rwlock_destroy(&round.rwlock) != 0 && status == 0)
        status = 10;
    if (errno != E2BIG && status == 0)
        status = 11;
    return status;
}

struct shared_rwlock_round {
    pthread_rwlock_t rwlock;
    volatile int child_entered;
    volatile int child_acquired;
    volatile int child_lock_result;
    volatile int child_unlock_result;
};

static int wait_for_child(long child, int *status)
{
    long result;

    do {
        result = raw_syscall4(SYS_wait4, child, (long)(void *)status, 0, 0);
    } while (result == -EINTR);
    return result == child ? 0 : -1;
}

static int run_process_shared_case(int parent_holds_writer)
{
    long mapped = raw_syscall6(SYS_mmap, 0, SHARED_MAPPING_BYTES,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    struct shared_rwlock_round *round;
    pthread_rwlockattr_t attribute;
    long child;
    int child_status = -1;
    int status = 0;

    if (raw_failed(mapped))
        return 1;
    round = (struct shared_rwlock_round *)(void *)mapped;
    errno = E2BIG;
    if (pthread_rwlockattr_init(&attribute) != 0 ||
        pthread_rwlockattr_setpshared(&attribute, PTHREAD_PROCESS_SHARED) != 0 ||
        pthread_rwlock_init(&round->rwlock, &attribute) != 0 ||
        pthread_rwlockattr_destroy(&attribute) != 0) {
        (void)raw_syscall2(SYS_munmap, mapped, SHARED_MAPPING_BYTES);
        return 2;
    }
    if ((parent_holds_writer ? pthread_rwlock_wrlock(&round->rwlock) :
        pthread_rwlock_rdlock(&round->rwlock)) != 0) {
        (void)raw_syscall2(SYS_munmap, mapped, SHARED_MAPPING_BYTES);
        return 3;
    }
    child = raw_syscall0(SYS_fork);
    if (child < 0) {
        (void)pthread_rwlock_unlock(&round->rwlock);
        (void)raw_syscall2(SYS_munmap, mapped, SHARED_MAPPING_BYTES);
        return 4;
    }
    if (child == 0) {
        struct timespec deadline;
        int result = EINVAL;
        int unlock_result = -1;

        __atomic_store_n(&round->child_entered, 1, __ATOMIC_RELEASE);
        if (deadline_after(CLOCK_REALTIME, &deadline, FIXTURE_TIMEOUT_SECONDS) == 0)
            result = parent_holds_writer
                ? pthread_rwlock_timedrdlock(&round->rwlock, &deadline)
                : pthread_rwlock_timedwrlock(&round->rwlock, &deadline);
        __atomic_store_n(&round->child_lock_result, result, __ATOMIC_RELEASE);
        if (result == 0) {
            __atomic_store_n(&round->child_acquired, 1, __ATOMIC_RELEASE);
            unlock_result = pthread_rwlock_unlock(&round->rwlock);
        }
        __atomic_store_n(&round->child_unlock_result, unlock_result, __ATOMIC_RELEASE);
        raw_exit(result == 0 && unlock_result == 0 ? 0 : 1);
    }

    if (wait_for_int(&round->child_entered, 1) != 0 ||
        wait_for_waiter_mark((volatile int *)&round->rwlock.__u.__i[0]) != 0)
        status = 5;
    if (pthread_rwlock_unlock(&round->rwlock) != 0 && status == 0)
        status = 6;
    if (wait_for_child(child, &child_status) != 0 && status == 0)
        status = 7;
    if (status == 0 && (((child_status & 0x7f) != 0) ||
        ((child_status >> 8) & 0xff) != 0 ||
        __atomic_load_n(&round->child_lock_result, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&round->child_unlock_result, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&round->child_acquired, __ATOMIC_ACQUIRE) != 1))
        status = 8;
    if (pthread_rwlock_destroy(&round->rwlock) != 0 && status == 0)
        status = 9;
    if (raw_syscall2(SYS_munmap, mapped, SHARED_MAPPING_BYTES) != 0 && status == 0)
        status = 10;
    if (errno != E2BIG && status == 0)
        status = 11;
    return status;
}

int crabc_x86_64_pthread_rwlock_probe(void)
{
    int round;
    int status;

    errno = E2BIG;
    status = run_static_initializer_probe();
    if (status != 0)
        return status;
    status = run_attribute_and_private_probe();
    if (status != 0)
        return 20 + status;
    status = run_timed_status_probe();
    if (status != 0)
        return 40 + status;
    status = run_timed_futex_timeout_case(1);
    if (status != 0)
        return 60 + status;
    status = run_timed_futex_timeout_case(0);
    if (status != 0)
        return 75 + status;
    status = run_timed_release_probe();
    if (status != 0)
        return 90 + status;
    for (round = 0; round != CONTENTION_ROUNDS; ++round) {
        status = run_reader_concurrency_round();
        if (status != 0)
            return 120 + round * 20 + status;
        status = run_writer_exclusion_round();
        if (status != 0)
            return 190 + round * 20 + status;
    }
    status = run_process_shared_case(1);
    if (status != 0)
        return 260 + status;
    status = run_process_shared_case(0);
    if (status != 0)
        return 275 + status;
    return errno == E2BIG ? 0 : 290;
}

#ifndef CRABC_PTHREAD_RWLOCK_FREESTANDING
int main(void)
{
    return crabc_x86_64_pthread_rwlock_probe();
}
#endif
