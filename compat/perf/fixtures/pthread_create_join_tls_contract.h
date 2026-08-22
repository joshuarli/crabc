/*
 * One create/join operation with observable static and key-based TLS state.
 *
 * The parent writes a value that cannot equal the child's static TLS initial
 * value. The worker must start from that initializer, publish an independent
 * pthread-key value, and return its sequence-derived result. After join, the
 * parent must still observe its own value. Both the direct Musl differential
 * and the timed performance fixture include this exact contract.
 */
#ifndef CRABC_PTHREAD_CREATE_JOIN_TLS_CONTRACT_H
#define CRABC_PTHREAD_CREATE_JOIN_TLS_CONTRACT_H

#include <pthread.h>
#include <stdint.h>

struct pthread_create_join_tls_round {
    pthread_key_t key;
    unsigned int sequence;
};

static __thread unsigned int pthread_create_join_tls_state = 17U;

static void *pthread_create_join_tls_worker(void *opaque)
{
    const struct pthread_create_join_tls_round *const round = opaque;
    const unsigned int expected = (round->sequence & 0x0fffU) + 1U;

    if (pthread_create_join_tls_state != 17U)
        return NULL;
    pthread_create_join_tls_state = expected;
    if (pthread_setspecific(round->key, (void *)(uintptr_t)expected) != 0
            || pthread_getspecific(round->key) != (void *)(uintptr_t)expected)
        return NULL;
    return (void *)(uintptr_t)expected;
}

static int pthread_create_join_tls_round_run(pthread_key_t key, unsigned int sequence)
{
    const unsigned int expected = (sequence & 0x0fffU) + 1U;
    const unsigned int parent_value = 0x60000000U | expected;
    const struct pthread_create_join_tls_round round = {key, sequence};
    pthread_t thread;
    void *result = NULL;

    pthread_create_join_tls_state = parent_value;
    if (pthread_create(&thread, NULL, pthread_create_join_tls_worker, (void *)&round) != 0)
        return 1;
    if (pthread_join(thread, &result) != 0)
        return 2;
    if (result != (void *)(uintptr_t)expected)
        return 3;
    if (pthread_create_join_tls_state != parent_value)
        return 4;
    return 0;
}

#endif
