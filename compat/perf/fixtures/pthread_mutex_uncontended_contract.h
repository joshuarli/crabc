/*
 * One deterministic normal-mutex ownership path.
 *
 * The protected value changes only while the mutex is held. The caller checks
 * every lock/unlock result and the exact final value, so this is not a naked
 * lock micro-loop whose synchronization can be optimized away or silently
 * weakened. The direct Musl differential and performance fixture share it.
 */
#ifndef CRABC_PTHREAD_MUTEX_UNCONTENDED_CONTRACT_H
#define CRABC_PTHREAD_MUTEX_UNCONTENDED_CONTRACT_H

#include <pthread.h>
#include <stdint.h>

static int pthread_mutex_uncontended_run(unsigned long long iterations,
        uint64_t *observed)
{
    pthread_mutex_t mutex;
    uint64_t protected_value = 0;

    if (pthread_mutex_init(&mutex, NULL) != 0)
        return 1;
    for (unsigned long long i = 0; i < iterations; ++i) {
        if (pthread_mutex_lock(&mutex) != 0)
            return 2;
        protected_value += 1;
        if (pthread_mutex_unlock(&mutex) != 0)
            return 3;
    }
    if (pthread_mutex_destroy(&mutex) != 0)
        return 4;
    if (protected_value != iterations)
        return 5;
    *observed = protected_value;
    return 0;
}

#endif
