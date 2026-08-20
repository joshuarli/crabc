#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

/* This fixture intentionally uses the conventional static libc.a path.  It
 * checks both ELF TLS initialisation and the pthread key destructor lifecycle
 * without introducing an allocator-specific assertion. */
static _Thread_local int tls_value = 11;
static pthread_key_t key;
static int destructor_calls;

static void key_destructor(void *value)
{
    if (value != NULL)
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
    if (destructor_calls != 1)
        return 6;
    /* The worker's TLS instance must not modify the caller's instance. */
    if (tls_value != 11)
        return 7;
    if (pthread_key_delete(key) != 0)
        return 8;

    puts("static pthread tls ok");
    return 0;
}
