#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* This fixture intentionally uses the conventional static libc.a path.  It
 * checks ELF TLS initialisation, both normal-return and pthread_exit TSD
 * lifecycles, and public allocation during the user destructor phase. The C
 * backend still owns malloc; the paired Rust lifecycle test and static-root
 * TLS audit bind this observable ordering to crabc-mimalloc's private hook. */
static _Thread_local int tls_value = 11;
static pthread_key_t key;
static int destructor_calls;
static int destructor_allocation_failed;

static void key_destructor(void *value)
{
    void *allocation;

    if (value == NULL)
        return;
    allocation = malloc(37);
    if (allocation == NULL) {
        destructor_allocation_failed = 1;
        return;
    }
    free(allocation);
    destructor_calls++;
}

static void *worker(void *argument)
{
    int *observed = argument;
    *observed = tls_value;
    tls_value = 29;
    if (pthread_setspecific(key, argument) != 0)
        return (void *)(uintptr_t)1;
    return (void *)(uintptr_t)tls_value;
}

static void *pthread_exit_worker(void *argument)
{
    if (pthread_setspecific(key, argument) != 0)
        return (void *)(uintptr_t)1;
    pthread_exit((void *)(uintptr_t)41);
}

int main(void)
{
    if (tls_value != 11)
        return 1;
    if (pthread_key_create(&key, key_destructor) != 0)
        return 2;

    int observed = -1;
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, &observed) != 0)
        return 3;

    void *result = NULL;
    if (pthread_join(thread, &result) != 0)
        return 4;
    if (observed != 11 || (uintptr_t)result != 29)
        return 5;
    if (destructor_calls != 1 || destructor_allocation_failed)
        return 6;
    /* The worker's TLS instance must not modify the caller's instance. */
    if (tls_value != 11)
        return 7;
    if (pthread_create(&thread, NULL, pthread_exit_worker, &observed) != 0)
        return 8;
    result = NULL;
    if (pthread_join(thread, &result) != 0)
        return 9;
    if ((uintptr_t)result != 41 || destructor_calls != 2 || destructor_allocation_failed)
        return 10;
    if (pthread_key_delete(key) != 0)
        return 11;

    puts("static pthread tls ok");
    return 0;
}
