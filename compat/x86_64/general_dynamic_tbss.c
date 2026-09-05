#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

/* PT_TLS has no initialized prefix. Its 8 KiB per-thread zero fill is not
 * required to occupy bytes in any PT_LOAD of the executable. */
static _Alignas(4096) _Thread_local volatile unsigned char initial_zero[8192];
struct worker_result { uintptr_t address; int error; };

static int check_zero(void) {
    if ((uintptr_t)initial_zero % 4096 != 0) return 1;
    for (unsigned i = 0; i < sizeof initial_zero; i++) {
        if (initial_zero[i] != 0) return 2;
    }
    return 0;
}

static void *worker(void *argument) {
    struct worker_result *result = argument;
    result->address = (uintptr_t)initial_zero;
    result->error = check_zero();
    initial_zero[0] = 41;
    initial_zero[sizeof initial_zero - 1] = 43;
    return 0;
}

int main(void) {
    if (check_zero()) return 1;
    initial_zero[0] = 19;
    initial_zero[sizeof initial_zero - 1] = 23;
    struct worker_result result = { 0, 0 };
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, &result) || pthread_join(thread, 0)) return 2;
    if (result.error || result.address == (uintptr_t)initial_zero) return 3;
    if (initial_zero[0] != 19 || initial_zero[sizeof initial_zero - 1] != 23) return 4;
    puts("initial-tbss=8192,worker=isolated");
    return 0;
}
