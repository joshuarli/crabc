/* Direct pinned-Musl differential for the selected normal-mutex fast path. */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#include "../../compat/perf/fixtures/pthread_mutex_uncontended_contract.h"

int main(void)
{
    pthread_mutex_t mutex;
    uint64_t observed = 0;

    if (pthread_mutex_uncontended_run(1000000, &observed) != 0
            || observed != 1000000)
        return 1;
    if (pthread_mutex_init(&mutex, NULL) != 0)
        return 2;
    if (pthread_mutex_lock(&mutex) != 0)
        return 3;
    if (pthread_mutex_trylock(&mutex) != EBUSY)
        return 4;
    if (pthread_mutex_unlock(&mutex) != 0 || pthread_mutex_destroy(&mutex) != 0)
        return 5;
    puts("pthread mutex uncontended contract ok");
    return 0;
}
