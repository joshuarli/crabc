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
#include <sys/mman.h>
#include <sys/wait.h>
#include "pthread_futex_wait_witness.h"

struct shared_state {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    atomic_int ready[2];
    atomic_int completed;
    atomic_ulong child_address[2];
    int permits;
};
static void child_wait(struct shared_state *state, int index, int timed)
{
    /* Separate addresses prove the condition stores shared futex state and
     * never follows another process's automatic waiter pointers. */
    void *destination = mmap(0, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (destination == MAP_FAILED || destination == state) _Exit(20);
    void *moved = (void *)syscall(SYS_mremap, state, 4096, 4096,
        MREMAP_MAYMOVE | MREMAP_FIXED, destination);
    if (moved != destination) _Exit(21);
    state = moved;
    if (pthread_mutex_lock(&state->mutex)) _Exit(22);
    atomic_store(&state->child_address[index], (unsigned long)(uintptr_t)&state->condition);
    atomic_store(&state->ready[index], 1);
    struct timespec until;
    if (clock_gettime(CLOCK_MONOTONIC, &until)) _Exit(23);
    until.tv_sec += 30;
    while (!state->permits) {
        int status = timed ? pthread_cond_timedwait(&state->condition, &state->mutex, &until) :
            pthread_cond_wait(&state->condition, &state->mutex);
        if (status) _Exit(24);
    }
    --state->permits;
    atomic_fetch_add(&state->completed, 1);
    if (pthread_mutex_unlock(&state->mutex)) _Exit(25);
    _Exit(0);
}
int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    int timed = !strcmp(argv[1], "timed");
    struct shared_state *state = mmap(0, 4096, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED) return 2;
    pthread_condattr_t cond_attr;
    pthread_mutexattr_t mutex_attr;
    if (pthread_mutexattr_init(&mutex_attr) ||
        pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED) ||
        pthread_mutex_init(&state->mutex, &mutex_attr) || pthread_mutexattr_destroy(&mutex_attr) ||
        pthread_condattr_init(&cond_attr) ||
        pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED) ||
        pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC) ||
        pthread_cond_init(&state->condition, &cond_attr) || pthread_condattr_destroy(&cond_attr)) return 3;
    pid_t children[2];
    for (int index = 0; index != 2; ++index) {
        children[index] = fork();
        if (children[index] < 0) return 4;
        if (!children[index]) child_wait(state, index, timed);
    }
    for (int index = 0; index != 2; ++index) {
        while (!atomic_load(&state->ready[index])) sched_yield();
        unsigned long address = atomic_load(&state->child_address[index]);
        if (!address || address == (unsigned long)(uintptr_t)&state->condition) return 5;
        /* Musl's shared sequence futex is the public word at byte eight. */
        witness_process_futex_wait_at(children[index], children[index], 0, address + 8);
    }
    if (pthread_mutex_lock(&state->mutex)) return 6;
    state->permits = 1;
    if (pthread_cond_signal(&state->condition) || pthread_mutex_unlock(&state->mutex)) return 7;
    while (atomic_load(&state->completed) != 1) sched_yield();
    if (pthread_mutex_lock(&state->mutex)) return 8;
    state->permits = 1;
    if (pthread_cond_broadcast(&state->condition) || pthread_mutex_unlock(&state->mutex)) return 9;
    for (int index = 0; index != 2; ++index) {
        int status;
        if (waitpid(children[index], &status, 0) != children[index] || !WIFEXITED(status) || WEXITSTATUS(status)) return 10;
    }
    if (atomic_load(&state->completed) != 2 || pthread_cond_destroy(&state->condition) ||
        pthread_mutex_destroy(&state->mutex) || munmap(state, 4096)) return 11;
    puts("shared condition signal/broadcast across distinct process mappings: PASS");
    return 0;
}
