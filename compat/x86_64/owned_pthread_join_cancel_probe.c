#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include "pthread_futex_wait_witness.h"

enum join_mode {
    JOIN_ORDINARY,
    JOIN_TIMED,
};

static pthread_t target;
static atomic_int ready, release_target, cleanup_ran;
static int pending_entry, saved_state, cleanup_rejoin;
static atomic_int target_reaped, joiner_tid;
static enum join_mode selected_join_mode;

/* One common fixture object runs against pinned musl and every owned entry.
 * Musl waits on its private detach-state futex while the selected owned join
 * waits on the kernel-cleared shared child-TID word. The runner supplies the
 * expected operation for that linked runtime without changing this object. */
static unsigned long selected_join_futex_operation(void)
{
    const char *operation = getenv("CRABC_TEST_PTHREAD_JOIN_FUTEX_OPERATION");
    if (!operation) _Exit(61);
    if (!strcmp(operation, "0")) return 0;
    if (!strcmp(operation, "128")) return 128;
    _Exit(62);
}

static struct timespec realtime_after(long milliseconds)
{
    struct timespec result;
    if (clock_gettime(CLOCK_REALTIME, &result)) _Exit(60);
    result.tv_sec += milliseconds / 1000;
    result.tv_nsec += (milliseconds % 1000) * 1000000L;
    if (result.tv_nsec >= 1000000000L) {
        result.tv_sec++;
        result.tv_nsec -= 1000000000L;
    }
    return result;
}

static void *target_body(void *unused)
{
    (void)unused;
    while (!atomic_load(&release_target)) sched_yield();
    return (void *)(uintptr_t)37;
}

static int selected_join(void **result)
{
    if (selected_join_mode == JOIN_TIMED) {
        struct timespec deadline = realtime_after(10000);
        return pthread_timedjoin_np(target, result, &deadline);
    }
    return pthread_join(target, result);
}

static void cleanup(void *unused)
{
    (void)unused;
    if (cleanup_rejoin) {
        void *result = 0;
        atomic_store(&release_target, 1);
        if (pthread_join(target, &result) || result != (void *)(uintptr_t)37) _Exit(16);
        atomic_store(&target_reaped, 1);
    }
    atomic_store(&cleanup_ran, 1);
}

static void *joiner_body(void *unused)
{
    (void)unused;
    pthread_cleanup_push(cleanup, 0);
    if (saved_state && pthread_setcancelstate(saved_state, 0)) _Exit(12);
    if ((pending_entry || saved_state) && pthread_cancel(pthread_self())) _Exit(10);
    atomic_store(&joiner_tid, (int)syscall(SYS_gettid));
    atomic_store(&ready, 1);
    void *result = 0;
    if (selected_join(&result)) _Exit(11);
    if (saved_state) {
        int observed = -1;
        if (result != (void *)(uintptr_t)37 ||
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &observed) || observed != saved_state) _Exit(13);
        atomic_store(&target_reaped, 1);
        if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0)) _Exit(14);
        pthread_testcancel();
        _Exit(15);
    }
    pthread_cleanup_pop(0);
    return (void *)(uintptr_t)99;
}

/* A pending request does not make tryjoin a cancellation point while the
 * target remains joinable. The following explicit testcancel must deliver it. */
static void *tryjoin_pending_busy_body(void *unused)
{
    (void)unused;
    void *result = (void *)(uintptr_t)0x1234;
    pthread_cleanup_push(cleanup, 0);
    if (pthread_cancel(pthread_self())) _Exit(30);
    atomic_store(&joiner_tid, (int)syscall(SYS_gettid));
    atomic_store(&ready, 1);
    errno = E2BIG;
    if (pthread_tryjoin_np(target, &result) != EBUSY ||
        result != (void *)(uintptr_t)0x1234 || errno != E2BIG) _Exit(31);
    pthread_testcancel();
    _Exit(32);
    pthread_cleanup_pop(0);
}

/* Once the target exits, tryjoin delegates to pthread_join and must become a
 * cancellation point. Busy retries above remain non-canceling. */
static void *tryjoin_pending_exited_body(void *unused)
{
    (void)unused;
    void *result = (void *)(uintptr_t)0x1234;
    pthread_cleanup_push(cleanup, 0);
    if (pthread_cancel(pthread_self())) _Exit(33);
    atomic_store(&joiner_tid, (int)syscall(SYS_gettid));
    atomic_store(&ready, 1);
    errno = E2BIG;
    for (;;) {
        int status = pthread_tryjoin_np(target, &result);
        if (status == EBUSY) {
            if (result != (void *)(uintptr_t)0x1234 || errno != E2BIG) _Exit(34);
            sched_yield();
            continue;
        }
        _Exit(35);
    }
    pthread_cleanup_pop(0);
}

static int tryjoin_status_case(void)
{
    void *result = (void *)(uintptr_t)0x1234;
    atomic_store(&release_target, 0);
    if (pthread_create(&target, 0, target_body, 0)) return 40;
    errno = E2BIG;
    if (pthread_tryjoin_np(target, &result) != EBUSY ||
        result != (void *)(uintptr_t)0x1234 || errno != E2BIG) return 41;
    atomic_store(&release_target, 1);
    for (int attempt = 0; attempt != 1000000; ++attempt) {
        int status = pthread_tryjoin_np(target, &result);
        if (!status) {
            if (result != (void *)(uintptr_t)37 || errno != E2BIG) return 42;
            puts("pthread tryjoin busy/result preservation: PASS");
            return 0;
        }
        if (status != EBUSY) return 43;
        sched_yield();
    }
    return 44;
}

static int timed_status_case(void)
{
    void *result = (void *)(uintptr_t)0x1234;
    struct timespec past = { .tv_sec = 0, .tv_nsec = 0 };
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = 1000000000L };
    atomic_store(&release_target, 0);
    if (pthread_create(&target, 0, target_body, 0)) return 45;
    errno = E2BIG;
    if (pthread_timedjoin_np(target, &result, &past) != ETIMEDOUT ||
        result != (void *)(uintptr_t)0x1234 || errno != E2BIG) return 46;
    if (pthread_timedjoin_np(target, &result, &invalid) != EINVAL ||
        result != (void *)(uintptr_t)0x1234 || errno != E2BIG) return 47;
    struct timespec future = realtime_after(20);
    if (pthread_timedjoin_np(target, &result, &future) != ETIMEDOUT ||
        result != (void *)(uintptr_t)0x1234 || errno != E2BIG) return 48;
    atomic_store(&release_target, 1);
    if (pthread_join(target, &result) || result != (void *)(uintptr_t)37 || errno != E2BIG) return 49;
    puts("pthread timedjoin timeout/deadline/result preservation: PASS");
    return 0;
}

/* Musl reads abstime only from its wait loop. Once the target has exited, an
 * invalid deadline must therefore not prevent the final result/reclamation. */
static int timed_exited_invalid_deadline_case(void)
{
    void *result = (void *)(uintptr_t)0x1234;
    struct timespec invalid = { .tv_sec = 0, .tv_nsec = 1000000000L };
    atomic_store(&release_target, 1);
    if (pthread_create(&target, 0, target_body, 0)) return 50;
    errno = E2BIG;
    for (int attempt = 0; attempt != 1000000; ++attempt) {
        int status = pthread_timedjoin_np(target, &result, &invalid);
        if (!status) {
            if (result != (void *)(uintptr_t)37 || errno != E2BIG) return 51;
            puts("pthread timedjoin exited-target deadline ordering: PASS");
            return 0;
        }
        if (status != EINVAL || result != (void *)(uintptr_t)0x1234 || errno != E2BIG) return 52;
        sched_yield();
    }
    return 53;
}

static int join_cancellation_case(const char *scenario)
{
    pending_entry = !strcmp(scenario, "entry") || !strcmp(scenario, "timed-entry");
    cleanup_rejoin = !strcmp(scenario, "cleanup-rejoin") ||
        !strcmp(scenario, "try-pending-busy") || !strcmp(scenario, "try-pending-exited");
    selected_join_mode = !strncmp(scenario, "timed-", 6) ? JOIN_TIMED : JOIN_ORDINARY;
    saved_state = !strcmp(scenario, "disabled") || !strcmp(scenario, "timed-disabled")
        ? PTHREAD_CANCEL_DISABLE
        : !strcmp(scenario, "masked") || !strcmp(scenario, "timed-masked")
        ? PTHREAD_CANCEL_MASKED
        : 0;
    if (pending_entry) atomic_store(&release_target, 1);
    if (pthread_create(&target, 0, target_body, 0)) return 2;
    pthread_t joiner;
    void *(*joiner_body_fn)(void *) = !strcmp(scenario, "try-pending-busy")
        ? tryjoin_pending_busy_body : !strcmp(scenario, "try-pending-exited")
        ? tryjoin_pending_exited_body : joiner_body;
    if (pthread_create(&joiner, 0, joiner_body_fn, 0)) return 3;
    while (!atomic_load(&ready)) sched_yield();
    if (saved_state) atomic_store(&release_target, 1);
    else if (!strcmp(scenario, "try-pending-exited")) atomic_store(&release_target, 1);
    else if (!pending_entry && strcmp(scenario, "try-pending-busy")) {
        /* The target remains live until cancellation or user cleanup. */
        witness_pthread_futex_wait(
            atomic_load(&joiner_tid), selected_join_futex_operation());
        if (pthread_cancel(joiner)) return 4;
    }
    void *result = 0;
    if (pthread_join(joiner, &result) || result != PTHREAD_CANCELED ||
        !atomic_load(&cleanup_ran)) return 5;
    atomic_store(&release_target, 1);
    if (!atomic_load(&target_reaped) &&
        (pthread_join(target, &result) || result != (void *)(uintptr_t)37)) return 6;
    puts("pthread join cancellation and target reclamation: PASS");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    if (!strcmp(argv[1], "try-status")) return tryjoin_status_case();
    if (!strcmp(argv[1], "timed-status")) return timed_status_case();
    if (!strcmp(argv[1], "timed-exited-invalid")) return timed_exited_invalid_deadline_case();
    if (strcmp(argv[1], "entry") && strcmp(argv[1], "blocked") &&
        strcmp(argv[1], "disabled") && strcmp(argv[1], "masked") &&
        strcmp(argv[1], "cleanup-rejoin") && strcmp(argv[1], "timed-entry") &&
        strcmp(argv[1], "timed-blocked") && strcmp(argv[1], "timed-disabled") &&
        strcmp(argv[1], "timed-masked") && strcmp(argv[1], "try-pending-busy") &&
        strcmp(argv[1], "try-pending-exited")) return 7;
    return join_cancellation_case(argv[1]);
}
