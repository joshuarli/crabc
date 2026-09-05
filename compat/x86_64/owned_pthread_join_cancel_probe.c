#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include "pthread_futex_wait_witness.h"

static pthread_t target;
static atomic_int ready, release_target, cleanup_ran;
static int pending_entry, saved_state, cleanup_rejoin;
static atomic_int target_reaped, joiner_tid;
static void *target_body(void *unused)
{
    (void)unused;
    while (!atomic_load(&release_target)) sched_yield();
    return (void *)(uintptr_t)37;
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
    if (pthread_join(target, &result)) _Exit(11);
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
int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    pending_entry = !strcmp(argv[1], "entry");
    cleanup_rejoin = !strcmp(argv[1], "cleanup-rejoin");
    saved_state = !strcmp(argv[1], "disabled") ? PTHREAD_CANCEL_DISABLE :
        !strcmp(argv[1], "masked") ? PTHREAD_CANCEL_MASKED : 0;
    if (pending_entry) atomic_store(&release_target, 1);
    if (pthread_create(&target, 0, target_body, 0)) return 2;
    pthread_t joiner;
    if (pthread_create(&joiner, 0, joiner_body, 0)) return 3;
    while (!atomic_load(&ready)) sched_yield();
    if (saved_state) atomic_store(&release_target, 1);
    else if (!pending_entry) {
        /* The target remains live until cancellation or user cleanup. */
        /* Musl waits on its private detach state; owned joins wait on the
         * kernel-cleared shared child-TID word. Both targets are held live. */
#ifdef CRABC_OWNED_WITNESS
        witness_pthread_futex_wait(atomic_load(&joiner_tid), 0);
#else
        witness_pthread_futex_wait(atomic_load(&joiner_tid), 128);
#endif
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
