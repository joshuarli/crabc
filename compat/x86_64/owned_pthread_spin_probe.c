#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Each counter and its complement are published only through the spinlock.
 * Contending threads/processes must observe a complete preceding update. */
struct state {
    pthread_spinlock_t lock;
    unsigned count;
    unsigned complement;
};

static void require(int condition)
{
    if (!condition) _Exit(91);
}

static void initialize(struct state *state, int sharing)
{
    require(pthread_spin_init(&state->lock, sharing) == 0);
    state->count = 0;
    state->complement = ~0u;
    errno = E2BIG;
    require(pthread_spin_trylock(&state->lock) == 0);
    require(pthread_spin_trylock(&state->lock) == EBUSY);
    require(pthread_spin_unlock(&state->lock) == 0);
    require(errno == E2BIG);
}

static void *increment(void *argument)
{
    struct state *state = argument;
    for (unsigned i = 0; i < 20000; i++) {
        errno = EDOM;
        require(pthread_spin_lock(&state->lock) == 0);
        require(state->complement == ~state->count);
        state->count++;
        state->complement = ~state->count;
        require(pthread_spin_unlock(&state->lock) == 0);
        require(errno == EDOM);
    }
    return argument;
}

int main(void)
{
    struct state private;
    initialize(&private, PTHREAD_PROCESS_PRIVATE);
    pthread_t workers[4];
    for (unsigned i = 0; i < 4; i++)
        require(pthread_create(&workers[i], NULL, increment, &private) == 0);
    increment(&private);
    for (unsigned i = 0; i < 4; i++) {
        void *result = NULL;
        require(pthread_join(workers[i], &result) == 0 && result == &private);
    }
    require(private.count == 100000 && private.complement == ~private.count);
    require(pthread_spin_destroy(&private.lock) == 0);

    struct state *shared = mmap(NULL, sizeof *shared, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    require(shared != MAP_FAILED);
    initialize(shared, PTHREAD_PROCESS_SHARED);
    /* Force the child to observe a parent-owned lock before contention. */
    require(pthread_spin_lock(&shared->lock) == 0);
    int ready[2];
    require(pipe(ready) == 0);
    pid_t child = fork();
    require(child >= 0);
    if (!child) {
        require(close(ready[0]) == 0);
        require(pthread_spin_trylock(&shared->lock) == EBUSY);
        require(write(ready[1], "r", 1) == 1);
        require(close(ready[1]) == 0);
        increment(shared);
        _Exit(0);
    }
    require(close(ready[1]) == 0);
    char byte;
    require(read(ready[0], &byte, 1) == 1 && byte == 'r');
    require(close(ready[0]) == 0);
    require(pthread_spin_unlock(&shared->lock) == 0);
    increment(shared);
    int status;
    require(waitpid(child, &status, 0) == child);
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    require(shared->count == 40000 && shared->complement == ~shared->count);
    require(pthread_spin_destroy(&shared->lock) == 0);
    require(munmap(shared, sizeof *shared) == 0);
    puts("owned-pthread-spin-ok");
    return 0;
}
