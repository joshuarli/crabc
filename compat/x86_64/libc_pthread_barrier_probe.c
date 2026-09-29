/* Static crabc-libc x86-64 pthread-barrier fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6, then
 * as a true `-nostdlib -static` candidate linked only through the selected
 * crabc archive. It covers the complete public barrier surface: the four-byte
 * attribute lifecycle and pshared record, count validation, a reusable
 * process-private generations, signal interruption under contention, and
 * repeated shared-futex cross-fork generations with destruction and reinit.
 * Fixture-local raw syscalls provide mapping, process control, timing, signal
 * delivery, reporting, and exit plumbing without a C process runtime or CRT.
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
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 && sizeof(int) == 4,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(pthread_barrierattr_t) == 4 &&
    _Alignof(pthread_barrierattr_t) == 4,
    "musl x86 pthread_barrierattr_t layout");
_Static_assert(sizeof(pthread_barrier_t) == 32 && _Alignof(pthread_barrier_t) == 8,
    "musl x86 pthread_barrier_t layout");
_Static_assert(__builtin_offsetof(pthread_barrierattr_t, __attr) == 0,
    "pthread_barrierattr_t public word offset");
_Static_assert(PTHREAD_PROCESS_PRIVATE == 0 && PTHREAD_PROCESS_SHARED == 1,
    "musl pthread process-sharing values");
_Static_assert(PTHREAD_BARRIER_SERIAL_THREAD == -1,
    "musl serial barrier result");
_Static_assert(EINVAL == 22, "Linux x86 EINVAL");
_Static_assert(SYS_write == 1 && SYS_mmap == 9 && SYS_munmap == 11 && SYS_fork == 57 &&
    SYS_exit == 60 && SYS_wait4 == 61 && SYS_clock_gettime == 228 &&
    SYS_getpid == 39 && SYS_gettid == 186 && SYS_tgkill == 234,
    "x86 barrier fixture syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_barrierattr_init),
    int (*)(pthread_barrierattr_t *)), "pthread_barrierattr_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_barrierattr_destroy),
    int (*)(pthread_barrierattr_t *)), "pthread_barrierattr_destroy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_barrierattr_setpshared),
    int (*)(pthread_barrierattr_t *, int)), "pthread_barrierattr_setpshared declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_barrierattr_getpshared),
    int (*)(const pthread_barrierattr_t *, int *)), "pthread_barrierattr_getpshared declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_barrier_init),
    int (*)(pthread_barrier_t *__restrict, const pthread_barrierattr_t *__restrict,
        unsigned)), "pthread_barrier_init declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_barrier_destroy),
    int (*)(pthread_barrier_t *)), "pthread_barrier_destroy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_barrier_wait),
    int (*)(pthread_barrier_t *)), "pthread_barrier_wait declaration");

enum {
    FIXTURE_TIMEOUT_SECONDS = 3,
    PRIVATE_BARRIER_ROUNDS = 2,
    CONTENTION_ROUNDS = 64,
    SHARED_BARRIER_ROUNDS = 32,
    SHARED_MAPPING_BYTES = 4096,
    INVALID_BARRIER_COUNT = 0x80000000U,
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

static long raw_syscall3(long number, long argument_one, long argument_two,
    long argument_three)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three) : "rcx", "r11", "memory");
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

static int report_phase(const char *message, unsigned long length)
{
    return raw_syscall3(SYS_write, 1, (long)(const void *)message, length) ==
        (long)length ? 0 : -1;
}

#define REPORT_PHASE(message) report_phase(message, sizeof(message) - 1)

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

static int wait_for_delay(long nanoseconds)
{
    struct timespec start, now;

    if (raw_clock(CLOCK_MONOTONIC, &start) != 0)
        return -1;
    do {
        if (raw_clock(CLOCK_MONOTONIC, &now) != 0)
            return -1;
    } while ((now.tv_sec - start.tv_sec) * 1000000000L +
        now.tv_nsec - start.tv_nsec < nanoseconds);
    return 0;
}

static int wait_for_child(long child, int *status)
{
    long result;

    do {
        result = raw_syscall4(SYS_wait4, child, (long)(void *)status, 0, 0);
    } while (result == -EINTR);
    return result == child ? 0 : -1;
}

static void fill_barrier_words(pthread_barrier_t *barrier, int value)
{
    unsigned index;

    for (index = 0; index != 8; ++index)
        barrier->__u.__i[index] = value;
}

static int barrier_words_match(const pthread_barrier_t *barrier, int value)
{
    unsigned index;

    for (index = 0; index != 8; ++index)
        if (barrier->__u.__i[index] != value)
            return 0;
    return 1;
}

static int exactly_one_serial(int first, int second)
{
    return (first == PTHREAD_BARRIER_SERIAL_THREAD) +
        (second == PTHREAD_BARRIER_SERIAL_THREAD) == 1 &&
        ((first == 0 && second == PTHREAD_BARRIER_SERIAL_THREAD) ||
        (first == PTHREAD_BARRIER_SERIAL_THREAD && second == 0));
}

static int run_attribute_and_count_probe(void)
{
    pthread_barrierattr_t attribute;
    pthread_barrier_t barrier;
    int process_shared = -1;

    errno = E2BIG;
    attribute.__attr = 0xa5a50083U;
    if (pthread_barrierattr_init(&attribute) != 0 || attribute.__attr != 0)
        return 1;
    if (pthread_barrierattr_getpshared(&attribute, &process_shared) != 0 ||
        process_shared != PTHREAD_PROCESS_PRIVATE)
        return 2;
    if (pthread_barrierattr_setpshared(&attribute, PTHREAD_PROCESS_SHARED) != 0 ||
        attribute.__attr != 0x80000000U ||
        pthread_barrierattr_getpshared(&attribute, &process_shared) != 0 ||
        process_shared != PTHREAD_PROCESS_SHARED)
        return 3;
    if (pthread_barrierattr_setpshared(&attribute, -1) != EINVAL ||
        attribute.__attr != 0x80000000U ||
        pthread_barrierattr_setpshared(&attribute, 2) != EINVAL ||
        attribute.__attr != 0x80000000U)
        return 4;

    /* Destroy owns no resource and leaves musl's public attribute bytes alone. */
    if (pthread_barrierattr_destroy(&attribute) != 0 ||
        attribute.__attr != 0x80000000U)
        return 5;

    fill_barrier_words(&barrier, 0x5a5a5a5a);
    if (pthread_barrier_init(&barrier, 0, 0) != EINVAL ||
        !barrier_words_match(&barrier, 0x5a5a5a5a))
        return 6;
    if (pthread_barrier_init(&barrier, 0, INVALID_BARRIER_COUNT) != EINVAL ||
        !barrier_words_match(&barrier, 0x5a5a5a5a))
        return 7;
    if (pthread_barrier_init(0, 0, 0) != EINVAL ||
        pthread_barrier_init(0, 0, INVALID_BARRIER_COUNT) != EINVAL ||
        pthread_barrierattr_setpshared(0, -1) != EINVAL ||
        pthread_barrierattr_destroy(0) != 0)
        return 11;

    if (pthread_barrier_init(&barrier, 0, 1) != 0 ||
        barrier.__u.__i[2] != 0)
        return 8;
    if (pthread_barrier_wait(&barrier) != PTHREAD_BARRIER_SERIAL_THREAD ||
        pthread_barrier_destroy(&barrier) != 0)
        return 9;
    if (pthread_barrier_init(&barrier, 0, 1) != 0 ||
        pthread_barrier_wait(&barrier) != PTHREAD_BARRIER_SERIAL_THREAD ||
        pthread_barrier_destroy(&barrier) != 0)
        return 12;
    return errno == E2BIG ? 0 : 10;
}

struct contention_rounds {
    pthread_barrier_t barrier;
    volatile int arrived[CONTENTION_ROUNDS][3];
    int results[CONTENTION_ROUNDS][3];
    int worker_errno[2];
    volatile int next_worker_id;
};

static int contention_participant(struct contention_rounds *rounds, int id)
{
    unsigned generation;

    for (generation = 0; generation != CONTENTION_ROUNDS; ++generation) {
        __atomic_store_n(&rounds->arrived[generation][id], 1, __ATOMIC_RELEASE);
        rounds->results[generation][id] = pthread_barrier_wait(&rounds->barrier);
        for (int peer = 0; peer != 3; ++peer)
            if (__atomic_load_n(&rounds->arrived[generation][peer],
                    __ATOMIC_ACQUIRE) != 1)
                return 1;
    }
    return 0;
}

static void *contention_worker(void *opaque)
{
    struct contention_rounds *rounds = opaque;
    int id = __atomic_fetch_add(&rounds->next_worker_id, 1,
        __ATOMIC_RELAXED) + 1;
    int result;

    errno = EACCES;
    result = contention_participant(rounds, id);
    rounds->worker_errno[id - 1] = errno;
    return (void *)(uintptr_t)result;
}

static int run_contention_generations(void)
{
    struct contention_rounds rounds = { 0 };
    pthread_t workers[2];
    void *results[2];
    unsigned generation;
    int main_result;

    errno = E2BIG;
    if (pthread_barrier_init(&rounds.barrier, 0, 3) != 0)
        return 1;
    if (pthread_create(&workers[0], 0, contention_worker, &rounds) != 0)
        return 2;
    if (pthread_create(&workers[1], 0, contention_worker, &rounds) != 0)
        return 3;
    main_result = contention_participant(&rounds, 0);
    if (pthread_join(workers[0], &results[0]) != 0 ||
        pthread_join(workers[1], &results[1]) != 0)
        return 4;
    if (main_result != 0 || results[0] != 0 || results[1] != 0 ||
        rounds.worker_errno[0] != EACCES || rounds.worker_errno[1] != EACCES)
        return 5;
    for (generation = 0; generation != CONTENTION_ROUNDS; ++generation) {
        int serial = 0;
        for (int id = 0; id != 3; ++id) {
            int result = rounds.results[generation][id];
            serial += result == PTHREAD_BARRIER_SERIAL_THREAD;
            if (result != 0 && result != PTHREAD_BARRIER_SERIAL_THREAD)
                return 6;
        }
        if (serial != 1)
            return 7;
    }
    if (pthread_barrier_destroy(&rounds.barrier) != 0 ||
        pthread_barrier_init(&rounds.barrier, 0, 1) != 0 ||
        pthread_barrier_wait(&rounds.barrier) != PTHREAD_BARRIER_SERIAL_THREAD ||
        pthread_barrier_destroy(&rounds.barrier) != 0)
        return 8;
    return errno == E2BIG ? 0 : 9;
}

static volatile sig_atomic_t signal_deliveries;

static void barrier_signal_handler(int signal)
{
    if (signal == SIGUSR1)
        ++signal_deliveries;
}

struct interrupted_round {
    pthread_barrier_t barrier;
    volatile int entered[2];
    volatile long worker_tid[2];
    int result[2];
    int worker_errno[2];
};

struct interrupted_worker_context {
    struct interrupted_round *round;
    int id;
};

static void *interrupted_worker(void *opaque)
{
    struct interrupted_worker_context *context = opaque;
    struct interrupted_round *round = context->round;
    int id = context->id;

    errno = EACCES;
    __atomic_store_n(&round->worker_tid[id], raw_syscall0(SYS_gettid),
        __ATOMIC_RELEASE);
    __atomic_store_n(&round->entered[id], 1, __ATOMIC_RELEASE);
    round->result[id] = pthread_barrier_wait(&round->barrier);
    round->worker_errno[id] = errno;
    return 0;
}

static int run_signal_interrupted_barrier(void)
{
    struct interrupted_round round = { 0 };
    struct interrupted_worker_context context[2] = {
        { &round, 0 }, { &round, 1 }
    };
    struct sigaction action = { 0 }, old_action;
    pthread_t worker[2];
    int main_result;
    int serial;
    int status = 0;

    action.sa_handler = barrier_signal_handler;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGUSR1, &action, &old_action) != 0)
        return 1;
    if (pthread_barrier_init(&round.barrier, 0, 3) != 0)
        return 2;
    if (pthread_create(&worker[0], 0, interrupted_worker, &context[0]) != 0 ||
        pthread_create(&worker[1], 0, interrupted_worker, &context[1]) != 0)
        return 3;
    if (wait_for_int(&round.entered[0], 1) != 0 ||
        wait_for_int(&round.entered[1], 1) != 0 ||
        wait_for_delay(10000000L) != 0)
        return 4;
    if (raw_syscall3(SYS_tgkill, raw_syscall0(SYS_getpid),
            __atomic_load_n(&round.worker_tid[0], __ATOMIC_ACQUIRE), SIGUSR1) != 0)
        return 5;
    main_result = pthread_barrier_wait(&round.barrier);
    if (pthread_join(worker[0], 0) != 0 || pthread_join(worker[1], 0) != 0)
        status = 6;
    serial = (main_result == PTHREAD_BARRIER_SERIAL_THREAD) +
        (round.result[0] == PTHREAD_BARRIER_SERIAL_THREAD) +
        (round.result[1] == PTHREAD_BARRIER_SERIAL_THREAD);
    if (serial != 1 ||
        (main_result != 0 && main_result != PTHREAD_BARRIER_SERIAL_THREAD) ||
        (round.result[0] != 0 &&
            round.result[0] != PTHREAD_BARRIER_SERIAL_THREAD) ||
        (round.result[1] != 0 &&
            round.result[1] != PTHREAD_BARRIER_SERIAL_THREAD) ||
        signal_deliveries != 1 || round.worker_errno[0] != EACCES ||
        round.worker_errno[1] != EACCES)
        status = 7;
    if (pthread_barrier_destroy(&round.barrier) != 0 ||
        sigaction(SIGUSR1, &old_action, 0) != 0)
        status = 8;
    return status;
}

struct private_barrier_round {
    pthread_barrier_t barrier;
    volatile int worker_entered;
    int worker_results[PRIVATE_BARRIER_ROUNDS];
    int worker_errno;
};

static void *private_barrier_worker(void *opaque)
{
    struct private_barrier_round *round = opaque;
    unsigned index;

    errno = EACCES;
    __atomic_store_n(&round->worker_entered, 1, __ATOMIC_RELEASE);
    for (index = 0; index != PRIVATE_BARRIER_ROUNDS; ++index)
        round->worker_results[index] = pthread_barrier_wait(&round->barrier);
    round->worker_errno = errno;
    return (void *)(uintptr_t)0x1122334455667788ULL;
}

static int run_private_thread_barrier_probe(void)
{
    struct private_barrier_round round = { 0 };
    pthread_t thread;
    void *result = 0;
    int main_results[PRIVATE_BARRIER_ROUNDS];
    unsigned index;

    errno = E2BIG;
    if (pthread_barrier_init(&round.barrier, 0, 2) != 0)
        return 1;
    if (pthread_create(&thread, 0, private_barrier_worker, &round) != 0) {
        (void)pthread_barrier_destroy(&round.barrier);
        return 2;
    }
    if (wait_for_int(&round.worker_entered, 1) != 0) {
        (void)pthread_join(thread, 0);
        (void)pthread_barrier_destroy(&round.barrier);
        return 3;
    }
    for (index = 0; index != PRIVATE_BARRIER_ROUNDS; ++index)
        main_results[index] = pthread_barrier_wait(&round.barrier);
    if (pthread_join(thread, &result) != 0) {
        (void)pthread_barrier_destroy(&round.barrier);
        return 4;
    }
    if (result != (void *)(uintptr_t)0x1122334455667788ULL ||
        round.worker_errno != EACCES)
        return 5;
    for (index = 0; index != PRIVATE_BARRIER_ROUNDS; ++index)
        if (!exactly_one_serial(main_results[index], round.worker_results[index]))
            return 6 + (int)index;
    if (pthread_barrier_destroy(&round.barrier) != 0)
        return 8;
    return errno == E2BIG ? 0 : 9;
}

struct shared_barrier_round {
    pthread_barrier_t barrier;
    volatile int child_entered;
    volatile int child_result[SHARED_BARRIER_ROUNDS];
    volatile int parent_arrived[SHARED_BARRIER_ROUNDS];
    volatile int child_arrived[SHARED_BARRIER_ROUNDS];
    volatile int child_errno;
};

static int run_process_shared_barrier_probe(void)
{
    long mapped = raw_syscall6(SYS_mmap, 0, SHARED_MAPPING_BYTES,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    struct shared_barrier_round *round;
    pthread_barrierattr_t attribute;
    long child;
    int child_status = -1;
    int parent_result;
    int parent_results[SHARED_BARRIER_ROUNDS];
    unsigned generation;
    int status = 0;

    if (raw_failed(mapped))
        return 1;
    round = (struct shared_barrier_round *)(void *)mapped;
    errno = E2BIG;
    if (pthread_barrierattr_init(&attribute) != 0 ||
        pthread_barrierattr_setpshared(&attribute, PTHREAD_PROCESS_SHARED) != 0 ||
        pthread_barrier_init(&round->barrier, &attribute, 2) != 0 ||
        pthread_barrierattr_destroy(&attribute) != 0) {
        (void)raw_syscall2(SYS_munmap, mapped, SHARED_MAPPING_BYTES);
        return 2;
    }
    if (round->barrier.__u.__i[2] >= 0) {
        (void)raw_syscall2(SYS_munmap, mapped, SHARED_MAPPING_BYTES);
        return 3;
    }
    child = raw_syscall0(SYS_fork);
    if (child < 0) {
        (void)pthread_barrier_destroy(&round->barrier);
        (void)raw_syscall2(SYS_munmap, mapped, SHARED_MAPPING_BYTES);
        return 4;
    }
    if (child == 0) {
        int child_result;

        errno = EACCES;
        __atomic_store_n(&round->child_entered, 1, __ATOMIC_RELEASE);
        for (generation = 0; generation != SHARED_BARRIER_ROUNDS; ++generation) {
            __atomic_store_n(&round->child_arrived[generation], 1, __ATOMIC_RELEASE);
            child_result = pthread_barrier_wait(&round->barrier);
            if (__atomic_load_n(&round->parent_arrived[generation],
                    __ATOMIC_ACQUIRE) != 1)
                raw_exit(2);
            __atomic_store_n(&round->child_result[generation], child_result,
                __ATOMIC_RELEASE);
        }
        __atomic_store_n(&round->child_errno, errno, __ATOMIC_RELEASE);
        raw_exit(0);
    }

    if (wait_for_int(&round->child_entered, 1) != 0)
        status = 5;
    for (generation = 0; generation != SHARED_BARRIER_ROUNDS; ++generation) {
        __atomic_store_n(&round->parent_arrived[generation], 1, __ATOMIC_RELEASE);
        parent_result = pthread_barrier_wait(&round->barrier);
        parent_results[generation] = parent_result;
        if (__atomic_load_n(&round->child_arrived[generation],
                __ATOMIC_ACQUIRE) != 1 && status == 0)
            status = 11;
    }
    if (pthread_barrier_destroy(&round->barrier) != 0 && status == 0)
        status = 8;
    if (wait_for_child(child, &child_status) != 0 && status == 0)
        status = 6;
    if (status == 0 && (((child_status & 0x7f) != 0) ||
        ((child_status >> 8) & 0xff) != 0 ||
        __atomic_load_n(&round->child_errno, __ATOMIC_ACQUIRE) != EACCES))
        status = 7;
    for (generation = 0; generation != SHARED_BARRIER_ROUNDS; ++generation)
        if (!exactly_one_serial(parent_results[generation],
                __atomic_load_n(&round->child_result[generation],
                    __ATOMIC_ACQUIRE)) && status == 0)
            status = 12;
    if (pthread_barrierattr_init(&attribute) != 0 ||
        pthread_barrierattr_setpshared(&attribute, PTHREAD_PROCESS_SHARED) != 0 ||
        pthread_barrier_init(&round->barrier, &attribute, 1) != 0 ||
        pthread_barrier_wait(&round->barrier) != PTHREAD_BARRIER_SERIAL_THREAD ||
        pthread_barrier_destroy(&round->barrier) != 0 ||
        pthread_barrierattr_destroy(&attribute) != 0)
        status = 13;
    if (raw_syscall2(SYS_munmap, mapped, SHARED_MAPPING_BYTES) != 0 && status == 0)
        status = 9;
    if (errno != E2BIG && status == 0)
        status = 10;
    return status;
}

int crabc_x86_64_pthread_barrier_probe(void)
{
    int status;

    status = run_attribute_and_count_probe();
    if (status != 0)
        return status;
    if (REPORT_PHASE("barrier-attributes-and-precedence: pass\n") != 0)
        return 90;
    status = run_private_thread_barrier_probe();
    if (status != 0)
        return 20 + status;
    if (REPORT_PHASE("barrier-private-basic: pass\n") != 0)
        return 91;
    status = run_contention_generations();
    if (status != 0)
        return 60 + status;
    if (REPORT_PHASE("barrier-private-generations-64: pass\n") != 0)
        return 92;
    status = run_signal_interrupted_barrier();
    if (status != 0)
        return 80 + status;
    if (REPORT_PHASE("barrier-signal-contention: pass\n") != 0)
        return 93;
    status = run_process_shared_barrier_probe();
    if (status != 0)
        return 40 + status;
    return REPORT_PHASE("barrier-shared-generations-32: pass\n") == 0 ? 0 : 94;
}

#if !defined(CRABC_PTHREAD_BARRIER_FREESTANDING)
int main(void)
{
    return crabc_x86_64_pthread_barrier_probe();
}
#endif
