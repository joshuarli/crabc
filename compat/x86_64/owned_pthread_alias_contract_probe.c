/*
 * Exercise musl 1.2.6's weak-public pthread/C11 alias boundary.
 *
 * The application supplies one strong public pthread_setcancelstate.  Its own
 * direct call must resolve there, while pthread_join reaches musl's hidden
 * __pthread_setcancelstate body as it restores cancellation state around its
 * wait.  The worker result gives that internal route a finite, synchronous
 * completion edge instead of a timing observation.  The address checks cover
 * the two source alias groups whose C11 names share pthread bodies.
 */
#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdint.h>
#include <threads.h>
#include <unistd.h>

static int public_setcancelstate_calls;

int pthread_setcancelstate(int state, int *old_state)
{
    (void)state;
    if (old_state != 0)
        *old_state = PTHREAD_CANCEL_ENABLE;
    ++public_setcancelstate_calls;
    return 0;
}

static void *worker(void *argument)
{
    return argument;
}

int main(void)
{
    static const char success[] = "owned-pthread-alias-contract-ok\n";
    pthread_t thread;
    void *joined = 0;
    int observed = -1;

    if ((uintptr_t)pthread_detach != (uintptr_t)thrd_detach)
        return 10;
    if ((uintptr_t)pthread_getspecific != (uintptr_t)tss_get)
        return 11;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &observed) != 0
        || observed != PTHREAD_CANCEL_ENABLE
        || public_setcancelstate_calls != 1)
        return 12;
    if (pthread_create(&thread, 0, worker, (void *)(uintptr_t)0x5a5a) != 0)
        return 13;
    if (pthread_join(thread, &joined) != 0 || joined != (void *)(uintptr_t)0x5a5a)
        return 14;
    if (public_setcancelstate_calls != 1)
        return 15;
    if (write(STDOUT_FILENO, success, sizeof(success) - 1) != (ssize_t)(sizeof(success) - 1))
        return 16;
    return 0;
}
