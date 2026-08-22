/*
 * Recycle more worker lifetimes than the fixed pthread slot table while
 * checking create/join publication and both static and pthread-key TLS.
 */
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>

#include "../../compat/perf/fixtures/pthread_create_join_tls_contract.h"

static pthread_key_t destructor_key;
static unsigned int destructor_calls;
static pthread_key_t slot_reuse_key;

static void rearming_destructor(void *value)
{
    (void)value;
    destructor_calls += 1;
    if (destructor_calls < PTHREAD_DESTRUCTOR_ITERATIONS)
        (void)pthread_setspecific(destructor_key,
                (void *)(uintptr_t)(destructor_calls + 1));
}

static void *destructor_worker(void *opaque)
{
    (void)opaque;
    if (pthread_setspecific(destructor_key, (void *)(uintptr_t)1) != 0)
        return (void *)(uintptr_t)1;
    return NULL;
}

static int test_rearming_destructor(void)
{
    pthread_t worker;
    void *result = (void *)(uintptr_t)1;

    destructor_calls = 0;
    if (pthread_key_create(&destructor_key, rearming_destructor) != 0)
        return 1;
    if (pthread_create(&worker, NULL, destructor_worker, NULL) != 0)
        return 2;
    if (pthread_join(worker, &result) != 0)
        return 3;
    if (result != NULL || destructor_calls != PTHREAD_DESTRUCTOR_ITERATIONS)
        return 4;
    if (pthread_key_delete(destructor_key) != 0)
        return 5;
    return 0;
}

static void *slot_reuse_worker(void *opaque)
{
    (void)opaque;
    if (pthread_getspecific(slot_reuse_key) != NULL)
        return (void *)(uintptr_t)1;
    if (pthread_setspecific(slot_reuse_key, (void *)(uintptr_t)1) != 0)
        return (void *)(uintptr_t)2;
    return NULL;
}

static int test_slot_reuse_clears_tsd(void)
{
    pthread_t worker;
    void *result;

    if (pthread_key_create(&slot_reuse_key, NULL) != 0)
        return 1;
    for (unsigned int round = 0; round < 2; ++round) {
        result = (void *)(uintptr_t)3;
        if (pthread_create(&worker, NULL, slot_reuse_worker, NULL) != 0)
            return 2;
        if (pthread_join(worker, &result) != 0)
            return 3;
        if (result != NULL)
            return 4;
    }
    if (pthread_key_delete(slot_reuse_key) != 0)
        return 5;
    return 0;
}

static int test_null_destructor_keys_reserve_capacity(void)
{
    pthread_key_t keys[PTHREAD_KEYS_MAX];
    pthread_key_t extra;

    for (unsigned int index = 0; index < PTHREAD_KEYS_MAX; ++index) {
        if (pthread_key_create(&keys[index], NULL) != 0)
            return 1;
    }
    if (pthread_key_create(&extra, NULL) != EAGAIN)
        return 2;
    for (unsigned int index = 0; index < PTHREAD_KEYS_MAX; ++index) {
        if (pthread_key_delete(keys[index]) != 0)
            return 3;
    }
    return 0;
}

int main(void)
{
    pthread_key_t key;

    if (pthread_key_create(&key, NULL) != 0)
        return 1;
    for (unsigned int sequence = 0; sequence < 513; ++sequence) {
        const int status = pthread_create_join_tls_round_run(key, sequence);
        if (status != 0)
            return 10 + status;
    }
    if (pthread_key_delete(key) != 0)
        return 20;
    if (test_rearming_destructor() != 0)
        return 30;
    if (test_slot_reuse_clears_tsd() != 0)
        return 40;
    if (test_null_destructor_keys_reserve_capacity() != 0)
        return 50;
    puts("pthread create/join tls contract ok");
    return 0;
}
