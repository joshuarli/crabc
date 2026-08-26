#include <errno.h>
#include <pthread.h>
#include <stdint.h>

struct worker_result {
    int *location;
    int initial_errno;
    int final_errno;
};

static void *worker(void *opaque)
{
    struct worker_result *result = opaque;

    result->location = __errno_location();
    result->initial_errno = errno;
    errno = E2BIG;
    result->final_errno = errno;
    return 0;
}

int main(void)
{
    pthread_t thread;
    struct worker_result result = {0};
    int *main_location = __errno_location();
    void *thread_return = (void *)(uintptr_t)1;

    if (main_location == 0 || errno != 0)
        return 10;

    errno = EACCES;
    if (errno != EACCES || __errno_location() != main_location)
        return 11;

    if (pthread_create(&thread, 0, worker, &result) != 0)
        return 12;
    if (pthread_join(thread, &thread_return) != 0 || thread_return != 0)
        return 13;

    if (result.location == 0 || result.location == main_location)
        return 14;
    if (result.initial_errno != 0 || result.final_errno != E2BIG)
        return 15;
    if (errno != EACCES || __errno_location() != main_location)
        return 16;

    return 0;
}
