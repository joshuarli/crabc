#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "pthread_futex_wait_witness.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static atomic_int ready, waiter_tid, cleaned, reuse_ready;
static pthread_t waiter;
static int main_waiter, pending_entry, saved_state, signaled;
#ifdef CRABC_SHARED_CONDITION
#define CONDITION_FUTEX_OPERATION 0
#else
#define CONDITION_FUTEX_OPERATION 128
#endif
static void cleanup(void *unused)
{
    (void)unused;
    /* No other task owns this mutex during cleanup: EBUSY proves relock. */
    if (pthread_mutex_trylock(&mutex) != EBUSY || pthread_mutex_unlock(&mutex)) _Exit(20);
    atomic_store(&cleaned, 1);
}
static void *wait_body(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&mutex)) _Exit(21);
    pthread_cleanup_push(cleanup, 0);
    if (saved_state && pthread_setcancelstate(saved_state, 0)) _Exit(22);
    if ((pending_entry || saved_state) && pthread_cancel(pthread_self())) _Exit(23);
    atomic_store(&waiter_tid, (int)syscall(SYS_gettid));
    atomic_store(&ready, 1);
#ifdef CRABC_TIMED_CONDITION
    struct timespec until;
    if (clock_gettime(CLOCK_MONOTONIC, &until)) _Exit(42);
    until.tv_sec += 30;
    int result = pthread_cond_timedwait(&condition, &mutex, &until);
#else
    int result = pthread_cond_wait(&condition, &mutex);
#endif
    if (signaled) {
        /* A consumed signal suppresses cancellation inside cond_wait, but
         * the request remains pending for this next explicit point. */
        if (result) _Exit(38);
        pthread_testcancel();
        _Exit(39);
    }
    if (!saved_state) _Exit(24);
    int observed = -1;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &observed)) _Exit(25);
    if (saved_state == PTHREAD_CANCEL_MASKED) {
        if (result != ECANCELED || observed != PTHREAD_CANCEL_DISABLE) _Exit(26);
    } else if (result || observed != PTHREAD_CANCEL_DISABLE) _Exit(27);
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0)) _Exit(28);
    pthread_testcancel();
    pthread_cleanup_pop(0);
    _Exit(29);
}
static void *reuse_body(void *unused)
{
    (void)unused;
    if (pthread_mutex_lock(&mutex)) _Exit(30);
    atomic_store(&reuse_ready, 1);
    if (pthread_cond_wait(&condition, &mutex) || pthread_mutex_unlock(&mutex)) _Exit(31);
    return (void *)(uintptr_t)42;
}
static void verify_reuse(void)
{
    pthread_t thread;
    if (pthread_create(&thread, 0, reuse_body, 0)) _Exit(32);
    while (!atomic_load(&reuse_ready)) sched_yield();
    /* Acquiring the released mutex proves the replacement is enrolled. */
    if (pthread_mutex_lock(&mutex) || pthread_cond_signal(&condition) ||
        pthread_mutex_unlock(&mutex)) _Exit(33);
    void *result = 0;
    if (pthread_join(thread, &result) || result != (void *)(uintptr_t)42 ||
        pthread_cond_destroy(&condition) || pthread_mutex_destroy(&mutex)) _Exit(34);
}
static void *controller(void *unused)
{
    (void)unused;
    while (!atomic_load(&ready)) sched_yield();
    if (!pending_entry && saved_state != PTHREAD_CANCEL_MASKED) {
        witness_pthread_futex_wait(atomic_load(&waiter_tid), CONDITION_FUTEX_OPERATION);
        if (signaled) {
            if (pthread_mutex_lock(&mutex) || pthread_cond_signal(&condition)) _Exit(40);
            /* Both public musl-compatible mutex layouts put the lock at byte4.
             * Hold it until the signaled waiter has reached its relock wait. */
            witness_pthread_futex_wait_at(atomic_load(&waiter_tid), CONDITION_FUTEX_OPERATION,
                (unsigned long)(uintptr_t)((char *)&mutex + 4));
            if (pthread_cancel(waiter) || pthread_mutex_unlock(&mutex)) _Exit(41);
        } else if (saved_state == PTHREAD_CANCEL_DISABLE) {
            if (pthread_mutex_lock(&mutex) || pthread_cond_signal(&condition) ||
                pthread_mutex_unlock(&mutex)) _Exit(35);
        } else if (pthread_cancel(waiter)) _Exit(36);
    }
    if (!main_waiter) {
        void *result = 0;
        if (pthread_join(waiter, &result) || result != PTHREAD_CANCELED) _Exit(37);
    }
    while (!atomic_load(&cleaned)) sched_yield();
    verify_reuse();
    puts("pthread condition cancellation, mutex reacquisition and reuse: PASS");
    return 0;
}
int main(int argc, char **argv)
{
    if (argc != 2) return 1;
#if defined(CRABC_TIMED_CONDITION) || defined(CRABC_SHARED_CONDITION)
    pthread_condattr_t cond_attr;
    if (pthread_condattr_init(&cond_attr)) return 4;
#ifdef CRABC_TIMED_CONDITION
    if (pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC)) return 5;
#endif
#ifdef CRABC_SHARED_CONDITION
    pthread_mutexattr_t mutex_attr;
    if (pthread_mutexattr_init(&mutex_attr) ||
        pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED) ||
        pthread_mutex_init(&mutex, &mutex_attr) || pthread_mutexattr_destroy(&mutex_attr) ||
        pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED)) return 6;
#endif
    if (pthread_cond_init(&condition, &cond_attr) || pthread_condattr_destroy(&cond_attr)) return 7;
#endif
    main_waiter = !strncmp(argv[1], "main-", 5);
    pending_entry = strstr(argv[1], "entry") != 0;
    signaled = strstr(argv[1], "signaled") != 0;
    saved_state = strstr(argv[1], "disabled") ? PTHREAD_CANCEL_DISABLE :
        strstr(argv[1], "masked") ? PTHREAD_CANCEL_MASKED : 0;
    pthread_t observer;
    if (main_waiter) {
        waiter = pthread_self();
        if (pthread_create(&observer, 0, controller, 0)) return 2;
        wait_body(0);
    } else {
        if (pthread_create(&waiter, 0, wait_body, 0)) return 3;
        controller(0);
    }
    return 0;
}
