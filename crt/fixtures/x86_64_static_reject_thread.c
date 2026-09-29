/* A live worker distinguishes process termination from main-thread exit when
 * the static CRT rejects a malformed finalizer array after main returns. */
#include <pthread.h>
#include <unistd.h>

static void *worker(void *unused)
{
    (void)unused;
    for (;;) pause();
}

int main(void)
{
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, 0)) return 93;
    return 0;
}
