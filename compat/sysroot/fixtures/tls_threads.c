/* Main, constructor, pthread, and errno TLS fixture. */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>

static __thread int fixture_tls = 31;
static int constructor_seen;

__attribute__((constructor)) static void fixture_constructor(void)
{
    constructor_seen = fixture_tls == 31;
}

static void *thread_main(void *argument)
{
    (void)argument;
    if (fixture_tls != 31)
        return (void *)(uintptr_t)1;
    fixture_tls = 47;
    errno = 29;
    if (fixture_tls != 47 || errno != 29)
        return (void *)(uintptr_t)2;
    return 0;
}

int main(void)
{
    pthread_t thread;
    void *result = 0;

    if (!constructor_seen || fixture_tls != 31)
        return 30;
    errno = 17;
    if (pthread_create(&thread, 0, thread_main, 0) != 0)
        return 31;
    if (pthread_join(thread, &result) != 0 || result != 0)
        return 32;
    return fixture_tls == 31 && errno == 17 ? 0 : 33;
}
