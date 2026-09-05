/*
 * Installed x86 pthread mutex extension regression.
 *
 * Each scenario observes a musl 1.2.6 mutex contract through project headers,
 * then the runner compares the same stdout-only witness across owned static
 * ET_EXEC/static-PIE and installed dynamic PIE/non-PIE products. The source
 * keeps each result local: a failure exit identifies the first broken state
 * transition without borrowing a host libc implementation.
 */

#define _GNU_SOURCE

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

#include "pthread_futex_wait_witness.h"

static pthread_mutex_t mutex;
static pthread_cond_t condition;
static pthread_t worker;
static atomic_int ready, release_worker, acquired, waiter_tid, wait_done, cleaned;

static void reset_state(void)
{
    atomic_store(&ready, 0);
    atomic_store(&release_worker, 0);
    atomic_store(&acquired, 0);
    atomic_store(&waiter_tid, 0);
    atomic_store(&wait_done, 0);
    atomic_store(&cleaned, 0);
}

static void wait_for(atomic_int *value)
{
    while (!atomic_load(value)) sched_yield();
}

static int init_mutex(int kind, int robust, int shared)
{
    pthread_mutexattr_t attributes;
    int result = pthread_mutexattr_init(&attributes);
    if (result) return result;
    result = pthread_mutexattr_settype(&attributes, kind);
    if (!result && robust)
        result = pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST);
    if (!result && shared)
        result = pthread_mutexattr_setpshared(&attributes, PTHREAD_PROCESS_SHARED);
    if (!result) result = pthread_mutex_init(&mutex, &attributes);
    int destroy = pthread_mutexattr_destroy(&attributes);
    return result ? result : destroy;
}

static struct timespec realtime_after(long milliseconds)
{
    struct timespec value;
    if (clock_gettime(CLOCK_REALTIME, &value)) _Exit(90);
    value.tv_nsec += milliseconds * 1000000;
    value.tv_sec += value.tv_nsec / 1000000000;
    value.tv_nsec %= 1000000000;
    return value;
}

static void *recursive_contender(void *unused)
{
    (void)unused;
    atomic_store(&ready, 1);
    if (pthread_mutex_lock(&mutex)) _Exit(10);
    atomic_store(&acquired, 1);
    if (pthread_mutex_unlock(&mutex)) _Exit(11);
    return 0;
}

static int recursive_case(void)
{
    reset_state();
    if (init_mutex(PTHREAD_MUTEX_RECURSIVE, 0, 0)) return 12;
    errno = E2BIG;
    if (pthread_mutex_lock(&mutex) || pthread_mutex_lock(&mutex) ||
        pthread_mutex_trylock(&mutex) || errno != E2BIG) return 13;
    if (pthread_create(&worker, 0, recursive_contender, 0)) return 14;
    wait_for(&ready);
    for (int index = 0; index != 1000; ++index) sched_yield();
    if (atomic_load(&acquired)) return 15;
    if (pthread_mutex_unlock(&mutex) || atomic_load(&acquired)) return 16;
    if (pthread_mutex_unlock(&mutex) || atomic_load(&acquired)) return 17;
    if (pthread_mutex_unlock(&mutex) || pthread_join(worker, 0) ||
        !atomic_load(&acquired) || errno != E2BIG || pthread_mutex_destroy(&mutex)) return 18;
    puts("pthread recursive ownership, depth and contention: PASS");
    return 0;
}

static void *wrong_owner_unlock(void *unused)
{
    (void)unused;
    return (void *)(intptr_t)pthread_mutex_unlock(&mutex);
}

static int errorcheck_case(void)
{
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = -1 };
    reset_state();
    if (init_mutex(PTHREAD_MUTEX_ERRORCHECK, 0, 0) || pthread_mutex_lock(&mutex)) return 20;
    errno = E2BIG;
    if (pthread_mutex_trylock(&mutex) != EBUSY || pthread_mutex_lock(&mutex) != EDEADLK ||
        pthread_mutex_timedlock(&mutex, &invalid) != EDEADLK || errno != E2BIG) return 21;
    if (pthread_create(&worker, 0, wrong_owner_unlock, 0)) return 22;
    void *result = 0;
    if (pthread_join(worker, &result) || (int)(intptr_t)result != EPERM) return 23;
    if (pthread_mutex_unlock(&mutex)) return 24;
    /* Musl locks an uncontended object before it looks at an invalid deadline. */
    if (pthread_mutex_timedlock(&mutex, &invalid) || pthread_mutex_unlock(&mutex) ||
        errno != E2BIG || pthread_mutex_destroy(&mutex)) return 25;
    puts("pthread error-checking self-owner and wrong-owner status: PASS");
    return 0;
}

static void *timed_holder(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&mutex)) _Exit(30);
    atomic_store(&ready, 1);
    while (!atomic_load(&release_worker)) sched_yield();
    if (pthread_mutex_unlock(&mutex)) _Exit(31);
    return 0;
}

static int timed_case(void)
{
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = -1 };
    struct timespec expired = { .tv_sec = -1, .tv_nsec = 0 };
    reset_state();
    if (pthread_mutex_init(&mutex, 0)) return 32;
    errno = E2BIG;
    if (pthread_mutex_timedlock(&mutex, &invalid) || pthread_mutex_unlock(&mutex) ||
        errno != E2BIG) return 33;
    if (pthread_create(&worker, 0, timed_holder, 0)) return 34;
    wait_for(&ready);
    if (pthread_mutex_timedlock(&mutex, &invalid) != EINVAL || errno != E2BIG ||
        pthread_mutex_timedlock(&mutex, &expired) != ETIMEDOUT || errno != E2BIG) return 35;
    struct timespec future = realtime_after(10);
    if (pthread_mutex_timedlock(&mutex, &future) != ETIMEDOUT || errno != E2BIG) return 36;
    atomic_store(&release_worker, 1);
    if (pthread_join(worker, 0) || pthread_mutex_destroy(&mutex)) return 37;
    puts("pthread timed realtime ordering, validation and errno: PASS");
    return 0;
}

static int robust_kind;
static void *dead_owner(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&mutex)) _Exit(40);
    if (robust_kind == PTHREAD_MUTEX_RECURSIVE && pthread_mutex_lock(&mutex)) _Exit(41);
    return 0;
}

static int robust_one_case(int kind, int shared)
{
    struct timespec future;
    reset_state();
    robust_kind = kind;
    if (init_mutex(kind, 1, shared) || pthread_cond_init(&condition, 0) ||
        pthread_create(&worker, 0, dead_owner, 0) || pthread_join(worker, 0)) return 42;
    errno = E2BIG;
    if (pthread_mutex_lock(&mutex) != EOWNERDEAD || errno != E2BIG) return 43;
    future = realtime_after(10);
    /* Musl denies a recovery owner before it can release/relock in a wait. */
    if (pthread_cond_timedwait(&condition, &mutex, &future) != EPERM || errno != E2BIG ||
        pthread_mutex_consistent(&mutex)) return 44;
    if (kind == PTHREAD_MUTEX_RECURSIVE &&
        (pthread_mutex_lock(&mutex) || pthread_mutex_unlock(&mutex))) return 45;
    if (pthread_mutex_unlock(&mutex) || pthread_mutex_lock(&mutex) ||
        pthread_mutex_unlock(&mutex) || pthread_cond_destroy(&condition) ||
        pthread_mutex_destroy(&mutex)) return 46;
    return 0;
}

static int robust_case(void)
{
    if (robust_one_case(PTHREAD_MUTEX_RECURSIVE, 0) ||
        robust_one_case(PTHREAD_MUTEX_ERRORCHECK, 0) ||
        robust_one_case(PTHREAD_MUTEX_RECURSIVE, 1) ||
        robust_one_case(PTHREAD_MUTEX_ERRORCHECK, 1)) return 47;
    puts("pthread robust recursive/error-checking owner death and pre-consistent condition admission: PASS");
    return 0;
}

static void recursive_cleanup(void *unused)
{
    (void)unused;
    /* Cancellation repairs the one-unlock condition transaction first. */
    if (pthread_mutex_trylock(&mutex) || pthread_mutex_unlock(&mutex) ||
        pthread_mutex_unlock(&mutex) || pthread_mutex_unlock(&mutex)) _Exit(50);
    atomic_store(&cleaned, 1);
}

static void *recursive_condition_waiter(void *argument)
{
    int cancel = (int)(intptr_t)argument;
    if (pthread_mutex_lock(&mutex) || pthread_mutex_lock(&mutex)) _Exit(51);
    pthread_cleanup_push(recursive_cleanup, 0);
    atomic_store(&waiter_tid, (int)syscall(SYS_gettid));
    atomic_store(&ready, 1);
    int result = pthread_cond_wait(&condition, &mutex);
    if (cancel || result) _Exit(52);
    /* Wait unlocked once and relocked once: the original depth is intact. */
    if (pthread_mutex_trylock(&mutex) || pthread_mutex_unlock(&mutex) ||
        pthread_mutex_unlock(&mutex) || pthread_mutex_unlock(&mutex)) _Exit(53);
    atomic_store(&wait_done, 1);
    pthread_cleanup_pop(0);
    return (void *)(intptr_t)77;
}

static int recursive_condition_case(void)
{
    reset_state();
    if (init_mutex(PTHREAD_MUTEX_RECURSIVE, 0, 0) || pthread_cond_init(&condition, 0) ||
        pthread_create(&worker, 0, recursive_condition_waiter, 0)) return 54;
    wait_for(&ready);
    for (int index = 0; index != 1000000 && !atomic_load(&wait_done); ++index) {
        if (pthread_cond_signal(&condition)) return 55;
        sched_yield();
    }
    void *result = 0;
    if (!atomic_load(&wait_done) || pthread_join(worker, &result) ||
        result != (void *)(intptr_t)77 || pthread_cond_destroy(&condition) ||
        pthread_mutex_destroy(&mutex)) return 56;

    reset_state();
    if (init_mutex(PTHREAD_MUTEX_RECURSIVE, 0, 0) || pthread_cond_init(&condition, 0) ||
        pthread_create(&worker, 0, recursive_condition_waiter, (void *)(intptr_t)1)) return 57;
    wait_for(&ready);
    witness_pthread_futex_wait(atomic_load(&waiter_tid), 128);
    if (pthread_cancel(worker) || pthread_join(worker, &result) ||
        result != PTHREAD_CANCELED || !atomic_load(&cleaned) ||
        pthread_cond_destroy(&condition) || pthread_mutex_destroy(&mutex)) return 58;
    puts("pthread recursive condition one-unlock relock and cancellation cleanup: PASS");
    return 0;
}

static mtx_t c11_mutex;
static atomic_int c11_ready, c11_release;

static int c11_holder(void *unused)
{
    (void)unused;
    if (mtx_lock(&c11_mutex) != thrd_success) return 60;
    atomic_store(&c11_ready, 1);
    while (!atomic_load(&c11_release)) thrd_yield();
    return mtx_unlock(&c11_mutex) == thrd_success ? 0 : 61;
}

static int c11_case(void)
{
    mtx_t recursive;
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = -1 };
    struct timespec expired = { .tv_sec = -1, .tv_nsec = 0 };
    if (mtx_init(&recursive, mtx_recursive | mtx_timed) != thrd_success ||
        mtx_lock(&recursive) != thrd_success || mtx_lock(&recursive) != thrd_success ||
        mtx_unlock(&recursive) != thrd_success || mtx_unlock(&recursive) != thrd_success) return 62;
    mtx_destroy(&recursive);
    if (mtx_init(&c11_mutex, mtx_timed) != thrd_success) return 63;
    errno = E2BIG;
    if (mtx_timedlock(&c11_mutex, &invalid) != thrd_success ||
        mtx_unlock(&c11_mutex) != thrd_success || errno != E2BIG) return 64;
    atomic_store(&c11_ready, 0);
    atomic_store(&c11_release, 0);
    thrd_t c11_worker;
    if (thrd_create(&c11_worker, c11_holder, 0) != thrd_success) return 65;
    while (!atomic_load(&c11_ready)) thrd_yield();
    if (mtx_timedlock(&c11_mutex, &invalid) != thrd_error || errno != E2BIG ||
        mtx_timedlock(&c11_mutex, &expired) != thrd_timedout || errno != E2BIG) return 66;
    atomic_store(&c11_release, 1);
    int result = -1;
    if (thrd_join(c11_worker, &result) != thrd_success || result || errno != E2BIG) return 67;
    mtx_destroy(&c11_mutex);
    puts("C11 recursive/timed kinds and timed mutex status: PASS");
    return 0;
}

/*
 * PI uses the Linux futex state machine, but this fixture never changes a
 * scheduler policy or priority.  It checks the pinned-musl ABI transition
 * under ordinary tasks: attribute admission, try/lock/timed lock, robust
 * private and process-shared death recovery, and the condition relock seam.
 */
static pthread_mutex_t pi_mutex;
static pthread_cond_t pi_condition;
static pthread_t pi_worker;
static atomic_int pi_ready, pi_release, pi_acquired;

/* Linux 5.10 classic-BPF ABI, kept fixture-local. The filter rejects only
 * FUTEX_TRYLOCK_PI|FUTEX_PRIVATE_FLAG. Pinned musl never issues that
 * operation from pthread_mutex_trylock, so a direct EBUSY result proves the
 * source's failed-owner/CAS path did not acquire through the kernel. */
struct pi_bpf_instruction {
    uint16_t code;
    uint8_t yes;
    uint8_t no;
    uint32_t value;
};

struct pi_bpf_program {
    uint16_t length;
    struct pi_bpf_instruction *instructions;
};

enum {
    PI_BPF_LD = 0x00,
    PI_BPF_W = 0x00,
    PI_BPF_ABS = 0x20,
    PI_BPF_JMP = 0x05,
    PI_BPF_JEQ = 0x10,
    PI_BPF_K = 0x00,
    PI_BPF_RET = 0x06,
    PI_SECCOMP_SET_MODE_FILTER = 1,
    PI_SECCOMP_RET_ALLOW = 0x7fff0000U,
    PI_SECCOMP_RET_ERRNO = 0x00050000U,
    PI_SECCOMP_ARGUMENT_ONE_LOW = 24,
    PI_FUTEX_TRYLOCK_PRIVATE = 8 | 128,
};

_Static_assert(sizeof(struct pi_bpf_instruction) == 8,
    "Linux classic-BPF instruction ABI");
_Static_assert(sizeof(struct pi_bpf_program) == 16 &&
    __builtin_offsetof(struct pi_bpf_program, instructions) == 8,
    "Linux sock_fprog ABI");
_Static_assert(SYS_futex == 202 && SYS_prctl == 157 && SYS_seccomp == 317,
    "Linux/x86-64 PI trylock source witness syscalls");

static int reject_kernel_pi_trylock(void)
{
    struct pi_bpf_instruction instructions[] = {
        { PI_BPF_LD | PI_BPF_W | PI_BPF_ABS, 0, 0, 0 },
        { PI_BPF_JMP | PI_BPF_JEQ | PI_BPF_K, 0, 3, SYS_futex },
        { PI_BPF_LD | PI_BPF_W | PI_BPF_ABS, 0, 0,
            PI_SECCOMP_ARGUMENT_ONE_LOW },
        { PI_BPF_JMP | PI_BPF_JEQ | PI_BPF_K, 0, 1,
            PI_FUTEX_TRYLOCK_PRIVATE },
        { PI_BPF_RET | PI_BPF_K, 0, 0, PI_SECCOMP_RET_ERRNO | EBADE },
        { PI_BPF_RET | PI_BPF_K, 0, 0, PI_SECCOMP_RET_ALLOW },
    };
    struct pi_bpf_program program = {
        .length = sizeof(instructions) / sizeof(instructions[0]),
        .instructions = instructions,
    };

    if (syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0)
        return -1;
    return syscall(SYS_seccomp, PI_SECCOMP_SET_MODE_FILTER, 0L,
        &program) == 0 ? 0 : -1;
}

static int init_pi_mutex(pthread_mutex_t *target, int kind, int robust, int shared)
{
    pthread_mutexattr_t attributes;
    int result = pthread_mutexattr_init(&attributes);
    if (!result) result = pthread_mutexattr_settype(&attributes, kind);
    if (!result) result = pthread_mutexattr_setprotocol(&attributes, PTHREAD_PRIO_INHERIT);
    if (!result && robust)
        result = pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST);
    if (!result && shared)
        result = pthread_mutexattr_setpshared(&attributes, PTHREAD_PROCESS_SHARED);
    if (!result) result = pthread_mutex_init(target, &attributes);
    int destroy = pthread_mutexattr_destroy(&attributes);
    return result ? result : destroy;
}

static void reset_pi_state(void)
{
    atomic_store(&pi_ready, 0);
    atomic_store(&pi_release, 0);
    atomic_store(&pi_acquired, 0);
}

static void *pi_holder(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&pi_mutex)) _Exit(70);
    atomic_store(&pi_ready, 1);
    while (!atomic_load(&pi_release)) sched_yield();
    if (pthread_mutex_unlock(&pi_mutex)) _Exit(71);
    return 0;
}

static void *pi_dead_owner(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&pi_mutex)) _Exit(72);
    return 0;
}

static void *pi_condition_waiter(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&pi_mutex)) _Exit(73);
    atomic_store(&pi_ready, 1);
    if (pthread_cond_wait(&pi_condition, &pi_mutex)) _Exit(74);
    atomic_store(&pi_acquired, 1);
    if (pthread_mutex_unlock(&pi_mutex)) _Exit(75);
    return 0;
}

static int pi_protocol_and_ceiling_case(void)
{
    pthread_mutexattr_t attributes;
    pthread_mutex_t opaque = { 0 };
    int protocol = -1;
    int ceiling = 0x5a5a1234;

    errno = E2BIG;
    if (pthread_mutexattr_setprotocol(0, -1) != EINVAL ||
        pthread_mutexattr_setprotocol(0, PTHREAD_PRIO_PROTECT) != ENOTSUP ||
        pthread_mutexattr_init(&attributes)) return 76;
    if (pthread_mutexattr_setprotocol(&attributes, PTHREAD_PRIO_NONE) ||
        pthread_mutexattr_getprotocol(&attributes, &protocol) ||
        protocol != PTHREAD_PRIO_NONE) return 77;
    if (pthread_mutexattr_setprotocol(&attributes, PTHREAD_PRIO_INHERIT) ||
        pthread_mutexattr_getprotocol(&attributes, &protocol) ||
        protocol != PTHREAD_PRIO_INHERIT) return 78;
    if (pthread_mutexattr_setprotocol(&attributes, PTHREAD_PRIO_PROTECT) != ENOTSUP ||
        pthread_mutexattr_setprotocol(&attributes, 3) != EINVAL || errno != E2BIG ||
        pthread_mutexattr_destroy(&attributes)) return 79;

    if (pthread_mutex_getprioceiling(0, 0) != EINVAL ||
        pthread_mutex_setprioceiling(0, 0, 0) != EINVAL ||
        pthread_mutex_getprioceiling(&opaque, &ceiling) != EINVAL ||
        ceiling != 0x5a5a1234 ||
        pthread_mutex_setprioceiling(&opaque, 7, &ceiling) != EINVAL ||
        ceiling != 0x5a5a1234 || errno != E2BIG) return 80;
    return 0;
}

static int pi_contention_and_deadline_case(void)
{
    struct timespec future;
    reset_pi_state();
    if (init_pi_mutex(&pi_mutex, PTHREAD_MUTEX_NORMAL, 0, 0) ||
        pthread_create(&pi_worker, 0, pi_holder, 0)) return 81;
    wait_for(&pi_ready);
    errno = E2BIG;
    future = realtime_after(10);
    if (pthread_mutex_trylock(&pi_mutex) != EBUSY ||
        pthread_mutex_timedlock(&pi_mutex, &future) != ETIMEDOUT || errno != E2BIG) return 82;
    atomic_store(&pi_release, 1);
    if (pthread_join(pi_worker, 0) || pthread_mutex_destroy(&pi_mutex)) return 83;

    if (init_pi_mutex(&pi_mutex, PTHREAD_MUTEX_ERRORCHECK, 0, 0) ||
        pthread_mutex_lock(&pi_mutex)) return 84;
    if (pthread_mutex_trylock(&pi_mutex) != EBUSY ||
        pthread_mutex_lock(&pi_mutex) != EDEADLK ||
        pthread_mutex_timedlock(&pi_mutex, &future) != EDEADLK ||
        pthread_mutex_unlock(&pi_mutex) || pthread_mutex_destroy(&pi_mutex) || errno != E2BIG) return 85;
    return 0;
}

/*
 * `__pthread_mutex_trylock_owner` has no FUTEX_TRYLOCK_PI fallback. The
 * target stays visibly owned while the caller's filter turns precisely that
 * invented operation into EBADE. Musl's direct owner check still returns
 * EBUSY without changing errno; a kernel fallback would expose EBADE.
 */
static int pi_trylock_source_failure_case(void)
{
    reset_pi_state();
    if (init_pi_mutex(&pi_mutex, PTHREAD_MUTEX_NORMAL, 0, 0) ||
        pthread_create(&pi_worker, 0, pi_holder, 0)) return 86;
    wait_for(&pi_ready);
    if (reject_kernel_pi_trylock() != 0) return 87;
    errno = E2BIG;
    if (pthread_mutex_trylock(&pi_mutex) != EBUSY || errno != E2BIG) return 88;
    atomic_store(&pi_release, 1);
    if (pthread_join(pi_worker, 0) || pthread_mutex_destroy(&pi_mutex)) return 89;
    return 0;
}

/*
 * This child deliberately constructs the private source-form PI waiter
 * sentinel after normal initialization. It is not an API for mutating an
 * opaque mutex: it isolates musl's post-CAS `(type&8) && _m_waiters` guard.
 * For a robust PI object that guard releases the kernel handoff and reports
 * ENOTRECOVERABLE rather than linking a usable owner record.
 */
static int pi_robust_waiter_guard_case(void)
{
    pid_t child = fork();
    if (child < 0) return 90;
    if (!child) {
        pthread_mutex_t local;

        if (init_pi_mutex(&local, PTHREAD_MUTEX_NORMAL, 1, 0)) _Exit(91);
        local.__u.__i[2] = 1;
        errno = E2BIG;
        if (pthread_mutex_trylock(&local) != ENOTRECOVERABLE || errno != E2BIG)
            _Exit(92);
        _Exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) return 93;
    return 0;
}

static int pi_robust_private_case(void)
{
    reset_pi_state();
    if (init_pi_mutex(&pi_mutex, PTHREAD_MUTEX_NORMAL, 1, 0) ||
        pthread_create(&pi_worker, 0, pi_dead_owner, 0) || pthread_join(pi_worker, 0)) return 86;
    errno = E2BIG;
    if (pthread_mutex_lock(&pi_mutex) != EOWNERDEAD || errno != E2BIG ||
        pthread_mutex_consistent(&pi_mutex) || pthread_mutex_unlock(&pi_mutex) ||
        pthread_mutex_destroy(&pi_mutex)) return 87;
    return 0;
}

struct pi_shared_state {
    pthread_mutex_t mutex;
};

static int pi_robust_shared_case(void)
{
    struct pi_shared_state *shared = mmap(0, sizeof(*shared), PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return 88;
    if (init_pi_mutex(&shared->mutex, PTHREAD_MUTEX_NORMAL, 1, 1)) return 89;
    pid_t child = fork();
    if (child < 0) return 90;
    if (!child) {
        int result = pthread_mutex_lock(&shared->mutex);
        _Exit(result ? 91 : 0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 92;
    errno = E2BIG;
    if (pthread_mutex_lock(&shared->mutex) != EOWNERDEAD || errno != E2BIG ||
        pthread_mutex_consistent(&shared->mutex) || pthread_mutex_unlock(&shared->mutex) ||
        pthread_mutex_destroy(&shared->mutex) || munmap(shared, sizeof(*shared))) return 93;
    return 0;
}

static int pi_condition_reacquire_case(void)
{
    struct timespec future;
    reset_pi_state();
    if (init_pi_mutex(&pi_mutex, PTHREAD_MUTEX_NORMAL, 0, 0) ||
        pthread_cond_init(&pi_condition, 0) ||
        pthread_create(&pi_worker, 0, pi_condition_waiter, 0)) return 94;
    wait_for(&pi_ready);
    if (pthread_mutex_lock(&pi_mutex) || pthread_cond_signal(&pi_condition)) return 95;
    for (int index = 0; index != 1000; ++index) sched_yield();
    if (atomic_load(&pi_acquired) || pthread_mutex_unlock(&pi_mutex) ||
        pthread_join(pi_worker, 0) || !atomic_load(&pi_acquired)) return 96;

    if (pthread_mutex_lock(&pi_mutex)) return 97;
    future = realtime_after(10);
    errno = E2BIG;
    if (pthread_cond_timedwait(&pi_condition, &pi_mutex, &future) != ETIMEDOUT ||
        errno != E2BIG || pthread_mutex_unlock(&pi_mutex) ||
        pthread_cond_destroy(&pi_condition) || pthread_mutex_destroy(&pi_mutex)) return 98;
    return 0;
}

static int pi_case(void)
{
    if (pi_protocol_and_ceiling_case() || pi_contention_and_deadline_case() ||
        pi_trylock_source_failure_case() || pi_robust_waiter_guard_case() ||
        pi_robust_private_case() || pi_robust_shared_case() ||
        pi_condition_reacquire_case()) return 99;
    puts("pthread PI protocol, direct trylock, robust owner death, condition relock, and rejected priority ceilings: PASS");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 80;
    if (!strcmp(argv[1], "recursive")) return recursive_case();
    if (!strcmp(argv[1], "errorcheck")) return errorcheck_case();
    if (!strcmp(argv[1], "timed")) return timed_case();
    if (!strcmp(argv[1], "robust")) return robust_case();
    if (!strcmp(argv[1], "recursive-condition")) return recursive_condition_case();
    if (!strcmp(argv[1], "c11")) return c11_case();
    if (!strcmp(argv[1], "pi")) return pi_case();
    return 81;
}
