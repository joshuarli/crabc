/* Private static x86-64 pthread_atfork/fork/exit-hook evidence.
 *
 * The same project-header body first runs against pinned musl 1.2.6 and then
 * through the selected no-allocation crabc archive. It proves one
 * single-threaded registered-hook sequence: prepare callbacks in reverse
 * order, parent/child callbacks in forward order, a child-only ordinary-exit
 * callback after its atfork callbacks, successful child reaping, a forced raw
 * fork error through the parent callback route, and candidate-only fixed-
 * capacity rejection plus a live-worker transaction, child reaping,
 * caller-owned TSD after fork, worker TSD isolation and destructor lifetime,
 * post-join admission recovery, and registration in a forked child before a
 * nested fork. The nested child reuses an unlocked mutex and inherited TSD;
 * the original parent retains its own handler set and TSD.
 * It does not select recursive callbacks, callback-driven worker creation,
 * foreign threads, concurrent selected-worker lifecycle,
 * signal safety, allocator, cancellation, contended or inherited-locked
 * synchronization, dynamic TLS, a
 * general fork/runtime exit protocol, CRT, loader, sysroot, or public x86
 * support.
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
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* This fixture uses a process-local classic-BPF filter only to force the raw
 * fork primitive to return a deterministic error. Public seccomp headers and
 * a general filter API are outside the selected static C surface. */
struct crabc_bpf_instruction {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t immediate;
};

struct crabc_bpf_program {
    uint16_t length;
    struct crabc_bpf_instruction *instructions;
};

enum {
    CRABC_BPF_LD = 0x00,
    CRABC_BPF_W = 0x00,
    CRABC_BPF_ABS = 0x20,
    CRABC_BPF_JMP = 0x05,
    CRABC_BPF_JEQ = 0x10,
    CRABC_BPF_K = 0x00,
    CRABC_BPF_RET = 0x06,
    CRABC_SECCOMP_SET_MODE_FILTER = 1,
    CRABC_SECCOMP_RET_ALLOW = 0x7fff0000U,
    CRABC_SECCOMP_RET_ERRNO = 0x00050000U,
};

#define CRABC_BPF_STATEMENT(instruction_code, value) \
    { (uint16_t)(instruction_code), 0, 0, (uint32_t)(value) }
#define CRABC_BPF_JUMP(instruction_code, value, yes, no) \
    { (uint16_t)(instruction_code), (uint8_t)(yes), (uint8_t)(no), \
      (uint32_t)(value) }

_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t layout");
_Static_assert(sizeof(struct crabc_bpf_instruction) == 8 &&
    __builtin_offsetof(struct crabc_bpf_program, instructions) == 8,
    "x86 classic-BPF filter ABI");
_Static_assert(SYS_read == 0 && SYS_write == 1 && SYS_close == 3 &&
    SYS_pipe == 22 && SYS_clone == 56 && SYS_fork == 57 && SYS_exit == 60 &&
    SYS_wait4 == 61 && SYS_prctl == 157 && SYS_exit_group == 231 &&
    SYS_seccomp == 317, "x86 selected and fixture-only atfork syscalls");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fork),
    pid_t (*)(void)), "fork declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_atfork),
    int (*)(void (*)(void), void (*)(void), void (*)(void))),
    "pthread_atfork declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&atexit),
    int (*)(void (*)(void))), "atexit declaration");
/* `_Noreturn` is part of the project declaration, so GCC does not regard its
 * function-pointer type as compatible with an unannotated `void (*)(int)` in
 * __builtin_types_compatible_p.  This initializer still asks the C checker to
 * admit exactly that callable parameter/result ABI while preserving the
 * header's no-return semantic. */
static void (*const exit_function_pointer)(int) = exit;

#ifdef CRABC_ATFORK_LOADER_HOOK_OVERRIDE
/*
 * Musl's static `fork.o` publishes this private hook as a weak no-op.  Taking
 * `fork`'s address extracts that archive member, then this caller-owned
 * strong spelling must still win without selecting a loader runtime.
 */
static volatile int loader_hook_calls;
static volatile int loader_hook_argument;

void __ldso_atfork(int who)
{
    ++loader_hook_calls;
    loader_hook_argument = who;
}

static int check_loader_hook_override(void)
{
    pid_t (*volatile extract_fork_member)(void) = fork;

    if (extract_fork_member == NULL)
        return 1;
    __ldso_atfork(-31);
    return loader_hook_calls == 1 && loader_hook_argument == -31 ? 0 : 2;
}
#endif

#ifdef CRABC_ATFORK_AIO_HOOK_OVERRIDE
/*
 * Musl's static `fork.o` also keeps this private AIO hook as a weak no-op;
 * `aio.o` owns its distinct strong lock-and-task implementation.  Extracting
 * `fork` must leave a caller-owned strong replacement in force.  The second
 * invocation traps, so the ordinary selected fork proof below also establishes
 * that this bounded fork path does not dispatch AIO behavior.
 */
static volatile int aio_hook_calls;
static volatile int aio_hook_argument;

void __aio_atfork(int who)
{
    ++aio_hook_calls;
    aio_hook_argument = who;
    if (aio_hook_calls != 1)
        __builtin_trap();
}

static int check_aio_hook_override(void)
{
    pid_t (*volatile extract_fork_member)(void) = fork;

    if (extract_fork_member == NULL)
        return 1;
    __aio_atfork(-47);
    return aio_hook_calls == 1 && aio_hook_argument == -47 ? 0 : 2;
}
#endif

static volatile unsigned int callback_phase;
static volatile int callback_failure;
static int child_report_write = -1;
static pthread_key_t main_tsd_key;
static pthread_key_t worker_tsd_key;
static _Atomic int selected_tsd_armed;
static _Atomic int worker_destructor_calls;
static _Atomic int worker_destructor_failure;
static pthread_key_t nested_tsd_key;
static pthread_mutex_t nested_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile unsigned int registration_depth;
static volatile int fork_error_expected;

enum { MAIN_TSD_VALUE = 0x4d, WORKER_TSD_VALUE = 0x57,
       NESTED_TSD_VALUE = 0x6e };

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
                         long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall5(long number, long argument1, long argument2,
                         long argument3, long argument4, long argument5)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5)
        : "rcx", "r11", "memory");
    return result;
}

static __attribute__((noreturn)) void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    __builtin_unreachable();
}

static int raw_close(int descriptor)
{
    return (int)raw_syscall1(SYS_close, descriptor);
}

static int raw_pipe(int descriptors[2])
{
    return (int)raw_syscall1(SYS_pipe, (long)descriptors);
}

static int raw_read_event(int descriptor, char *event)
{
    long result;

    do {
        result = raw_syscall3(SYS_read, descriptor, (long)event, 1);
    } while (result == -EINTR);
    return result == 1;
}

static int emit_child_event(char event)
{
    long result;

    do {
        result = raw_syscall3(SYS_write, child_report_write, (long)&event, 1);
    } while (result == -EINTR);
    return result == 1;
}

static void record_callback(unsigned int marker)
{
    static const unsigned int expected_initial[] = { 3, 2, 1, 4, 5, 6 };
    static const unsigned int expected_outer[] = { 7, 3, 2, 1, 4, 5, 6, 8 };
    static const unsigned int expected_nested[] = { 10, 7, 3, 2, 1,
                                                     4, 5, 6, 8, 9 };
    const unsigned int *expected = expected_initial;
    unsigned int count = sizeof(expected_initial) / sizeof(expected_initial[0]);

    if (registration_depth == 1) {
        expected = expected_outer;
        count = sizeof(expected_outer) / sizeof(expected_outer[0]);
    } else if (registration_depth == 2) {
        expected = expected_nested;
        count = sizeof(expected_nested) / sizeof(expected_nested[0]);
    }

    if (callback_phase >= count ||
        expected[callback_phase] != marker)
        callback_failure = 1;
    if (errno != (fork_error_expected && callback_phase >= 4 ? EPERM : E2BIG))
        callback_failure = 1;
    if (atomic_load_explicit(&selected_tsd_armed, memory_order_relaxed) != 0 &&
        (pthread_getspecific(main_tsd_key) !=
             (void *)(uintptr_t)MAIN_TSD_VALUE ||
         pthread_getspecific(worker_tsd_key) != NULL))
        callback_failure = 1;
    callback_phase++;
}

static void prepare_a(void) { record_callback(1); }
static void parent_a(void) { record_callback(4); }
static void child_a(void)
{
    record_callback(4);
    if (!emit_child_event('4'))
        raw_exit(120);
}

static void prepare_b(void) { record_callback(2); }
static void parent_b(void) { record_callback(5); }
static void child_b(void)
{
    record_callback(5);
    if (!emit_child_event('5'))
        raw_exit(121);
}

static void prepare_c(void) { record_callback(3); }
static void parent_c(void) { record_callback(6); }
static void child_c(void)
{
    record_callback(6);
    if (!emit_child_event('6'))
        raw_exit(122);
}

static void prepare_d(void) { record_callback(7); }
static void parent_d(void)
{
    record_callback(8);
    /* The final parent hook may change errno; fork restores its raw error. */
    if (fork_error_expected)
        errno = EALREADY;
}
static void child_d(void)
{
    record_callback(8);
    if (!emit_child_event('8'))
        raw_exit(127);
}

static void prepare_e(void) { record_callback(10); }
static void parent_e(void) { record_callback(9); }
static void child_e(void)
{
    record_callback(9);
    if (!emit_child_event('9'))
        raw_exit(128);
}

static void child_exit_callback(void)
{
    if (!emit_child_event('E'))
        raw_exit(123);
}

static int register_selected_hooks(void)
{
    errno = E2BIG;
    if (pthread_atfork(prepare_a, parent_a, child_a) != 0)
        return 1;
    if (pthread_atfork(prepare_b, parent_b, child_b) != 0)
        return 2;
    if (pthread_atfork(prepare_c, parent_c, child_c) != 0)
        return 3;
    if (pthread_atfork(NULL, NULL, NULL) != 0)
        return 4;
    return errno == E2BIG ? 0 : 5;
}

static int check_parent_child_and_exit_order(void)
{
    static const char expected_child_events[] = { '4', '5', '6', 'E' };
    int report[2] = { -1, -1 };
    int status = -1;
    pid_t child;
    pid_t waited;
    unsigned int index;

    if (raw_pipe(report) != 0)
        return 1;
    child_report_write = report[1];
    callback_phase = 0;
    callback_failure = 0;
    errno = E2BIG;
    child = fork();
    if (child < 0) {
        (void)raw_close(report[0]);
        (void)raw_close(report[1]);
        return 2;
    }
    if (child == 0) {
        if (callback_failure != 0 || callback_phase != 6 || errno != E2BIG)
            raw_exit(2);
        if (raw_close(report[0]) != 0)
            raw_exit(3);
        if (atexit(child_exit_callback) != 0)
            raw_exit(4);
        exit(0);
    }

    if (raw_close(report[1]) != 0)
        return 3;
    child_report_write = -1;
    if (callback_failure != 0 || callback_phase != 6)
        return 4;
    if (errno != E2BIG)
        return 5;

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child)
        return 6;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 7;
    for (index = 0; index < sizeof(expected_child_events); ++index) {
        char event = 0;

        if (!raw_read_event(report[0], &event) || event != expected_child_events[index])
            return 8 + (int)index;
    }
    {
        char unexpected = 0;
        if (raw_read_event(report[0], &unexpected))
            return 12;
    }
    if (raw_close(report[0]) != 0)
        return 13;
    return 0;
}

static int install_fork_error_filter(void)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_fork, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | EPERM),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_clone, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | EPERM),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
    };
    struct crabc_bpf_program program = {
        .length = (uint16_t)(sizeof(filter) / sizeof(filter[0])),
        .instructions = filter,
    };

    if (raw_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    if (raw_syscall3(SYS_seccomp, CRABC_SECCOMP_SET_MODE_FILTER, 0,
                     (long)(uintptr_t)&program) != 0)
        return -1;
    return 0;
}

static int check_raw_fork_error_parent_order(void)
{
    pid_t child;

    if (install_fork_error_filter() != 0)
        return 1;
    callback_phase = 0;
    callback_failure = 0;
    fork_error_expected = 1;
    errno = E2BIG;
    child = fork();
    if (child != -1)
        return 2;
    if (errno != EPERM)
        return 3;
    if (callback_failure != 0 || callback_phase != 8)
        return 4;
    return 0;
}

static _Atomic int selected_worker_ready;
static _Atomic int selected_worker_release;

static void worker_tsd_destructor(void *value)
{
    if (value != (void *)(uintptr_t)WORKER_TSD_VALUE ||
        pthread_getspecific(worker_tsd_key) != NULL)
        atomic_store_explicit(&worker_destructor_failure, 1, memory_order_release);
    atomic_fetch_add_explicit(&worker_destructor_calls, 1, memory_order_release);
}

static void *selected_live_worker(void *argument)
{
    if (pthread_getspecific(main_tsd_key) != NULL ||
        pthread_setspecific(worker_tsd_key,
            (void *)(uintptr_t)WORKER_TSD_VALUE) != 0 ||
        pthread_getspecific(worker_tsd_key) !=
            (void *)(uintptr_t)WORKER_TSD_VALUE)
        return NULL;
    atomic_store_explicit(&selected_worker_ready, 1, memory_order_release);
    while (atomic_load_explicit(&selected_worker_release, memory_order_acquire) == 0)
        ;
    return argument;
}

static int wait_for_selected_worker(void)
{
    unsigned long index;

    for (index = 0; index < 100000000UL; ++index) {
        if (atomic_load_explicit(&selected_worker_ready, memory_order_acquire) != 0)
            return 1;
    }
    return 0;
}

static int check_live_selected_worker_fork(void)
{
    static const char expected_child_events[] = { '4', '5', '6' };
    static const char trace[] =
        "atfork-tsd callbacks=321456 caller=retained worker=isolated destructor=once\n";
    pthread_t worker;
    void *result = 0;
    int report[2] = { -1, -1 };
    pid_t child;
    int status = -1;
    int failure = 0;
    unsigned int index;

    atomic_store_explicit(&worker_destructor_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&worker_destructor_failure, 0, memory_order_relaxed);
    atomic_store_explicit(&selected_worker_ready, 0, memory_order_relaxed);
    atomic_store_explicit(&selected_worker_release, 0, memory_order_relaxed);
    if (pthread_key_create(&main_tsd_key, NULL) != 0)
        return 1;
    if (pthread_key_create(&worker_tsd_key, worker_tsd_destructor) != 0)
        return 2;
    if (pthread_setspecific(main_tsd_key,
            (void *)(uintptr_t)MAIN_TSD_VALUE) != 0)
        return 3;
    if (pthread_create(&worker, NULL, selected_live_worker,
                       (void *)(uintptr_t)0x5a) != 0)
        return 4;
    if (!wait_for_selected_worker())
        failure = 5;
    if (raw_pipe(report) != 0)
        failure = failure == 0 ? 6 : failure;

    if (failure == 0) {
        child_report_write = report[1];
        callback_phase = 0;
        callback_failure = 0;
        atomic_store_explicit(&selected_tsd_armed, 1, memory_order_relaxed);
        errno = E2BIG;
        child = fork();
        if (child == 0) {
            if (callback_failure != 0 || callback_phase != 6 || errno != E2BIG)
                raw_exit(124);
            if (pthread_getspecific(main_tsd_key) !=
                    (void *)(uintptr_t)MAIN_TSD_VALUE ||
                pthread_getspecific(worker_tsd_key) != NULL)
                raw_exit(126);
            if (raw_close(report[0]) != 0)
                raw_exit(125);
            raw_exit(0);
        }
        atomic_store_explicit(&selected_tsd_armed, 0, memory_order_relaxed);
        if (child < 0) {
            failure = 4;
            (void)raw_close(report[0]);
            (void)raw_close(report[1]);
        } else {
            if (raw_close(report[1]) != 0)
                failure = 5;
            child_report_write = -1;
            if (callback_failure != 0 || callback_phase != 6 || errno != E2BIG)
                failure = failure == 0 ? 6 : failure;
            if (pthread_getspecific(main_tsd_key) !=
                    (void *)(uintptr_t)MAIN_TSD_VALUE ||
                pthread_getspecific(worker_tsd_key) != NULL)
                failure = failure == 0 ? 14 : failure;
            do {
                status = -1;
            } while (waitpid(child, &status, 0) < 0 && errno == EINTR);
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
                failure = failure == 0 ? 7 : failure;
            for (index = 0; index < sizeof(expected_child_events); ++index) {
                char event = 0;

                if (!raw_read_event(report[0], &event) ||
                    event != expected_child_events[index])
                    failure = failure == 0 ? 8 + (int)index : failure;
            }
            {
                char unexpected = 0;

                if (raw_read_event(report[0], &unexpected))
                    failure = failure == 0 ? 11 : failure;
            }
            if (raw_close(report[0]) != 0)
                failure = failure == 0 ? 12 : failure;
        }
    } else {
        (void)raw_close(report[0]);
        (void)raw_close(report[1]);
    }

    atomic_store_explicit(&selected_worker_release, 1, memory_order_release);
    if (pthread_join(worker, &result) != 0 || result != (void *)(uintptr_t)0x5a)
        failure = failure == 0 ? 13 : failure;
    if (atomic_load_explicit(&worker_destructor_calls, memory_order_acquire) != 1 ||
        atomic_load_explicit(&worker_destructor_failure, memory_order_acquire) != 0)
        failure = failure == 0 ? 15 : failure;
    if (pthread_getspecific(main_tsd_key) !=
            (void *)(uintptr_t)MAIN_TSD_VALUE ||
        pthread_getspecific(worker_tsd_key) != NULL)
        failure = failure == 0 ? 16 : failure;
    if (pthread_key_delete(worker_tsd_key) != 0 ||
        pthread_key_delete(main_tsd_key) != 0)
        failure = failure == 0 ? 17 : failure;
    if (failure == 0) {
        int recovery = check_parent_child_and_exit_order();

        if (recovery != 0)
            failure = 20 + recovery;
    }
    if (failure == 0 &&
        raw_syscall3(SYS_write, 1, (long)trace, sizeof(trace) - 1) !=
            (long)(sizeof(trace) - 1))
        failure = 18;
    return failure;
}

static int check_child_mutex_and_tsd(void)
{
    if (pthread_getspecific(nested_tsd_key) !=
            (void *)(uintptr_t)NESTED_TSD_VALUE)
        return 1;
    if (pthread_mutex_lock(&nested_mutex) != 0)
        return 2;
    if (pthread_mutex_unlock(&nested_mutex) != 0)
        return 3;
    if (pthread_setspecific(nested_tsd_key,
            (void *)(uintptr_t)(NESTED_TSD_VALUE + 1)) != 0)
        return 4;
    if (pthread_getspecific(nested_tsd_key) !=
            (void *)(uintptr_t)(NESTED_TSD_VALUE + 1))
        return 5;
    if (pthread_setspecific(nested_tsd_key,
            (void *)(uintptr_t)NESTED_TSD_VALUE) != 0)
        return 6;
    return errno == E2BIG ? 0 : 7;
}

static int read_nested_events(int descriptor, const char *expected,
                              unsigned int length)
{
    unsigned int index;

    for (index = 0; index < length; ++index) {
        char event = 0;

        if (!raw_read_event(descriptor, &event) || event != expected[index])
            return (int)index + 1;
    }
    return 0;
}

static int check_nested_registration_and_child_reuse(void)
{
    static const char expected_outer[] = "4568";
    static const char expected_nested[] = "45689NP";
    static const char expected_parent[] = "4568Q";
    static const char trace[] =
        "atfork-nested callbacks=73214568/10732145689 child=mutex-tsd parent=isolated errno=preserved\n";
    int report[2] = { -1, -1 };
    int status = -1;
    pid_t child;
    int result;

    if (pthread_key_create(&nested_tsd_key, NULL) != 0)
        return 1;
    if (pthread_setspecific(nested_tsd_key,
            (void *)(uintptr_t)NESTED_TSD_VALUE) != 0)
        return 2;
    if (pthread_atfork(prepare_d, parent_d, child_d) != 0)
        return 3;
    registration_depth = 1;
    if (raw_pipe(report) != 0)
        return 4;
    child_report_write = report[1];
    callback_phase = 0;
    callback_failure = 0;
    errno = E2BIG;
    child = fork();
    if (child < 0)
        return 5;
    if (child == 0) {
        pid_t nested;

        if (callback_failure != 0 || callback_phase != 8 || errno != E2BIG)
            raw_exit(130);
        if (raw_close(report[0]) != 0 || check_child_mutex_and_tsd() != 0)
            raw_exit(131);
        if (pthread_atfork(prepare_e, parent_e, child_e) != 0 ||
            errno != E2BIG)
            raw_exit(132);
        registration_depth = 2;
        callback_phase = 0;
        callback_failure = 0;
        errno = E2BIG;
        nested = fork();
        if (nested < 0)
            raw_exit(133);
        if (callback_failure != 0 || callback_phase != 10 || errno != E2BIG ||
            check_child_mutex_and_tsd() != 0)
            raw_exit(134);
        if (nested == 0) {
            if (!emit_child_event('N'))
                raw_exit(135);
            raw_exit(0);
        }
        if (waitpid(nested, &status, 0) != nested ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
            !emit_child_event('P'))
            raw_exit(136);
        raw_exit(0);
    }
    if (callback_failure != 0 || callback_phase != 8 || errno != E2BIG ||
        pthread_getspecific(nested_tsd_key) !=
            (void *)(uintptr_t)NESTED_TSD_VALUE)
        return 6;
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 7;
    if (raw_close(report[1]) != 0)
        return 8;
    child_report_write = -1;
    result = read_nested_events(report[0], expected_outer,
                                sizeof(expected_outer) - 1);
    if (result != 0)
        return 8 + result;
    result = read_nested_events(report[0], expected_nested,
                                sizeof(expected_nested) - 1);
    if (result != 0)
        return 13 + result;
    {
        char extra = 0;

        if (raw_read_event(report[0], &extra) || raw_close(report[0]) != 0)
            return 21;
    }
    if (raw_pipe(report) != 0)
        return 22;
    child_report_write = report[1];

    callback_phase = 0;
    callback_failure = 0;
    errno = E2BIG;
    child = fork();
    if (child < 0)
        return 22;
    if (child == 0) {
        if (callback_failure != 0 || callback_phase != 8 || errno != E2BIG ||
            check_child_mutex_and_tsd() != 0 || !emit_child_event('Q'))
            raw_exit(137);
        raw_exit(0);
    }
    if (callback_failure != 0 || callback_phase != 8 || errno != E2BIG)
        return 23;
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 24;
    if (raw_close(report[1]) != 0)
        return 30;
    child_report_write = -1;
    result = read_nested_events(report[0], expected_parent,
                                sizeof(expected_parent) - 1);
    if (result != 0)
        return 24 + result;
    {
        char extra = 0;

        if (raw_read_event(report[0], &extra))
            return 31;
    }
    if (raw_close(report[0]) != 0 ||
        pthread_getspecific(nested_tsd_key) !=
            (void *)(uintptr_t)NESTED_TSD_VALUE ||
        pthread_key_delete(nested_tsd_key) != 0)
        return 32;
    if (raw_syscall3(SYS_write, 1, (long)trace, sizeof(trace) - 1) !=
        (long)(sizeof(trace) - 1))
        return 33;
    return 0;
}

#ifdef CRABC_ATFORK_FREESTANDING
static int check_fixed_capacity_rejection(void)
{
    unsigned int index;

    /* Four real triples plus one empty triple preceded this candidate-only
     * closure check. Fill the fixed 32-record private registry exactly. */
    for (index = 0; index < 27; index++) {
        errno = E2BIG;
        if (pthread_atfork(NULL, NULL, NULL) != 0 || errno != E2BIG)
            return 1;
    }
    errno = E2BIG;
    if (pthread_atfork(NULL, NULL, NULL) != ENOMEM)
        return 2;
    return errno == E2BIG ? 0 : 3;
}
#endif

static int run_probe(void)
{
#ifdef CRABC_ATFORK_LOADER_HOOK_OVERRIDE
    return check_loader_hook_override();
#else
#ifdef CRABC_ATFORK_AIO_HOOK_OVERRIDE
    int aio_hook_status = check_aio_hook_override();

    if (aio_hook_status != 0)
        return 90 + aio_hook_status;
#endif
    int result = register_selected_hooks();

    if (result != 0)
        return result;
    result = check_parent_child_and_exit_order();
    if (result != 0)
        return 10 + result;
    result = check_live_selected_worker_fork();
    if (result != 0)
        return 40 + result;
    result = check_nested_registration_and_child_reuse();
    if (result != 0)
        return 100 + result;
#ifdef CRABC_ATFORK_FREESTANDING
    result = check_fixed_capacity_rejection();
    if (result != 0)
        return 30 + result;
#endif
    result = check_raw_fork_error_parent_order();
    if (result != 0)
        return 80 + result;
    return 0;
#endif
}

#ifdef CRABC_ATFORK_FREESTANDING
int crabc_x86_64_pthread_atfork_probe(void)
{
    return run_probe();
}
#else
int main(void)
{
    return run_probe();
}
#endif
