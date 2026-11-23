/*
 * Bounded SCHED_FIFO progress fixture for the selected pthread-key locks.
 *
 * The launcher pins every task to one CPU. One task is the SCHED_FIFO owner
 * (priority 10) looping over pthread-key operations; another is the higher
 * priority SCHED_FIFO waiter (priority 20). The waiter sleeps and wakes by
 * timer, preempting the owner at an arbitrary instruction, then runs a burst of
 * pthread_getspecific calls. If the owner is preempted while it holds a lock
 * that the burst needs and the waiter spins on it, neither can progress. An
 * external watchdog on another CPU observes the shared counters and kills the
 * process group.
 *
 * Scenarios (which task runs on the process-main thread differs, because a
 * worker's key lookup also takes the selected-worker registry lock and the
 * main thread's does not):
 *   getset    main owner: pthread_setspecific/pthread_getspecific; worker waiter.
 *   delete    worker owner: pthread_key_create/pthread_key_delete; main waiter.
 *   registry  worker owner: pthread_setspecific/pthread_getspecific; worker waiter.
 *   signal         no real-time policy: a handler calls pthread_getspecific on the main
 *                  thread while it loops over TSD operations.
 *   signal-worker  the same with the interrupted thread a worker.
 *
 * Exit status: 0 completed, 77 SCHED_FIFO unavailable, 1 failure.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#if !defined(__x86_64__) || !defined(__linux__)
#error "tsd_fifo_progress requires Linux/x86-64"
#endif

#define OWNER_PRIORITY 10
#define WAITER_PRIORITY 20

enum {
    PHASE_SETUP = 1,
    PHASE_FIFO = 2,
    PHASE_DONE = 3,
    PHASE_UNAVAILABLE = 4,
    PHASE_FAILED = 5,
};

struct shared {
    volatile uint64_t owner_ops;
    volatile uint64_t waiter_rounds;
    volatile uint64_t waiter_ops;
    volatile uint32_t phase;
    volatile uint32_t stop;
};

static struct shared *shared;
static volatile uint32_t waiter_ready;
static volatile uint32_t owner_go;
static pthread_key_t key;
static int owner_deletes;
static uint64_t rounds = 4000;
static uint64_t burst = 64;
static uint64_t budget_ms = 1500;

static long raw_syscall3(long number, long a, long b, long c)
{
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "0"(number), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return result;
}

static int set_policy(int policy, int priority)
{
    struct sched_param parameter;
    long result;

    memset(&parameter, 0, sizeof parameter);
    parameter.sched_priority = priority;
    result = raw_syscall3(144, 0, policy, (long)&parameter);
    return result < 0 ? (int)-result : 0;
}

static uint64_t now_ms(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static void fail(const char *message)
{
    shared->phase = PHASE_FAILED;
    dprintf(2, "tsd_fifo_progress: %s\n", message);
    _exit(1);
}

static void sleep_ns(long nanoseconds)
{
    struct timespec pause = {0, nanoseconds};

    nanosleep(&pause, 0);
}

static void *waiter(void *argument)
{
    uint64_t state = 0x9e3779b97f4a7c15u;
    uint64_t deadline;
    uint64_t round;
    int error;

    (void)argument;
    error = set_policy(SCHED_FIFO, WAITER_PRIORITY);
    if (error != 0) {
        shared->phase = PHASE_UNAVAILABLE;
        dprintf(2, "tsd_fifo_progress: SCHED_FIFO unavailable for waiter: errno %d\n", error);
        _exit(77);
    }
    if (pthread_setspecific(key, (void *)(uintptr_t)0x57a17e5) != 0) {
        fail("waiter setspecific failed");
    }
    __atomic_store_n(&waiter_ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&owner_go, __ATOMIC_ACQUIRE)) {
        sleep_ns(100000);
    }
    shared->phase = PHASE_FIFO;
    deadline = now_ms() + budget_ms;
    for (round = 0; round < rounds && now_ms() < deadline; round++) {
        uint64_t index;

        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        sleep_ns(50000 + (long)(state % 400000u));
        for (index = 0; index < burst; index++) {
            if (pthread_getspecific(key) != (void *)(uintptr_t)0x57a17e5) {
                fail("waiter observed the wrong value");
            }
        }
        shared->waiter_ops += burst;
        shared->waiter_rounds = round + 1;
    }
    __atomic_store_n(&shared->stop, 1, __ATOMIC_RELEASE);
    set_policy(SCHED_OTHER, 0);
    return 0;
}

static void *owner(void *argument)
{
    uint64_t operations = 0;
    int error;

    (void)argument;
    if (pthread_setspecific(key, (void *)(uintptr_t)0x0a11e5) != 0) fail("owner setspecific failed");
    while (!__atomic_load_n(&waiter_ready, __ATOMIC_ACQUIRE)) {
        sleep_ns(100000);
    }
    error = set_policy(SCHED_FIFO, OWNER_PRIORITY);
    if (error != 0) {
        shared->phase = PHASE_UNAVAILABLE;
        dprintf(2, "tsd_fifo_progress: SCHED_FIFO unavailable for owner: errno %d\n", error);
        _exit(77);
    }
    __atomic_store_n(&owner_go, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&shared->stop, __ATOMIC_ACQUIRE)) {
        if (owner_deletes) {
            pthread_key_t other;

            if (pthread_key_create(&other, 0) != 0) fail("owner key create failed");
            if (pthread_key_delete(other) != 0) fail("owner key delete failed");
        } else {
            if (pthread_setspecific(key, (void *)(uintptr_t)(0x0a11e5 + (operations & 1))) != 0) {
                fail("owner setspecific failed");
            }
            if ((uintptr_t)pthread_getspecific(key) != 0x0a11e5 + (operations & 1)) {
                fail("owner observed the wrong value");
            }
        }
        operations++;
        shared->owner_ops = operations;
    }
    set_policy(SCHED_OTHER, 0);
    return 0;
}

static volatile uint32_t handled;
static pthread_t signal_target;

static void handler(int number)
{
    (void)number;
    if (pthread_getspecific(key) == (void *)(uintptr_t)~(uintptr_t)0) fail("handler observed an impossible value");
    __atomic_add_fetch(&handled, 1, __ATOMIC_RELEASE);
}

static void *signal_victim(void *argument)
{
    uint64_t operations = 0;

    (void)argument;
    if (pthread_setspecific(key, (void *)(uintptr_t)0x0a11e5) != 0) fail("victim setspecific failed");
    signal_target = pthread_self();
    __atomic_store_n(&waiter_ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&shared->stop, __ATOMIC_ACQUIRE)) {
        if (pthread_setspecific(key, (void *)(uintptr_t)(0x0a11e5 + (operations & 1))) != 0) {
            fail("victim setspecific failed");
        }
        if ((uintptr_t)pthread_getspecific(key) != 0x0a11e5 + (operations & 1)) {
            fail("victim observed the wrong value");
        }
        operations++;
        shared->owner_ops = operations;
    }
    return 0;
}

static void *signaller(void *argument)
{
    uint64_t round;
    uint64_t deadline;

    (void)argument;
    while (!__atomic_load_n(&waiter_ready, __ATOMIC_ACQUIRE)) {
        sleep_ns(100000);
    }
    shared->phase = PHASE_FIFO;
    deadline = now_ms() + budget_ms;
    for (round = 0; round < rounds && now_ms() < deadline; round++) {
        uint32_t before = __atomic_load_n(&handled, __ATOMIC_ACQUIRE);

        if (pthread_kill(signal_target, SIGUSR1) != 0) fail("pthread_kill failed");
        while (__atomic_load_n(&handled, __ATOMIC_ACQUIRE) == before) {
            sleep_ns(20000);
        }
        shared->waiter_rounds = round + 1;
        sleep_ns(10000 + (long)(round % 7) * 3000);
    }
    __atomic_store_n(&shared->stop, 1, __ATOMIC_RELEASE);
    return 0;
}

static int run_signal(int victim_on_main)
{
    struct sigaction action;
    pthread_t thread;

    memset(&action, 0, sizeof action);
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0) != 0) fail("sigaction failed");
    if (victim_on_main) {
        if (pthread_create(&thread, 0, signaller, 0) != 0) fail("signaller create failed");
        signal_victim(0);
    } else {
        if (pthread_create(&thread, 0, signal_victim, 0) != 0) fail("victim create failed");
        signaller(0);
    }
    if (pthread_join(thread, 0) != 0) fail("join failed");
    shared->phase = PHASE_DONE;
    return 0;
}

int main(int argc, char **argv)
{
    pthread_t workers[2];
    int signal_scenario = 0;
    int owner_on_main;
    int waiter_on_main;
    int descriptor;
    int count = 0;

    if (argc < 3) {
        dprintf(2, "usage: %s PROGRESS_FILE getset|delete|registry|signal|signal-worker [rounds burst budget_ms]\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[2], "getset") == 0) {
        owner_on_main = 1;
        waiter_on_main = 0;
    } else if (strcmp(argv[2], "delete") == 0) {
        owner_on_main = 0;
        waiter_on_main = 1;
        owner_deletes = 1;
    } else if (strcmp(argv[2], "registry") == 0) {
        owner_on_main = 0;
        waiter_on_main = 0;
    } else if (strcmp(argv[2], "signal") == 0 || strcmp(argv[2], "signal-worker") == 0) {
        signal_scenario = argv[2][6] ? 2 : 1;
    } else {
        dprintf(2, "tsd_fifo_progress: unknown scenario %s\n", argv[2]);
        return 2;
    }
    if (argc > 3) rounds = strtoull(argv[3], 0, 10);
    if (argc > 4) burst = strtoull(argv[4], 0, 10);
    if (argc > 5) budget_ms = strtoull(argv[5], 0, 10);
    descriptor = open(argv[1], O_RDWR);
    if (descriptor < 0) {
        dprintf(2, "tsd_fifo_progress: cannot open %s\n", argv[1]);
        return 2;
    }
    shared = mmap(0, sizeof *shared, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, 0);
    if (shared == MAP_FAILED) {
        dprintf(2, "tsd_fifo_progress: cannot map progress file\n");
        return 2;
    }
    shared->phase = PHASE_SETUP;
    if (pthread_key_create(&key, 0) != 0) fail("key create failed");
    if (signal_scenario) return run_signal(signal_scenario == 1);
    if (!waiter_on_main && pthread_create(&workers[count++], 0, waiter, 0) != 0) fail("waiter create failed");
    if (!owner_on_main && pthread_create(&workers[count++], 0, owner, 0) != 0) fail("owner create failed");
    if (waiter_on_main) waiter(0);
    if (owner_on_main) owner(0);
    while (count > 0) {
        if (pthread_join(workers[--count], 0) != 0) fail("join failed");
    }
    shared->phase = PHASE_DONE;
    return 0;
}
