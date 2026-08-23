#include <threads.h>
#include <stdio.h>
#include <time.h>

static mtx_t mutex;
static cnd_t condition;
static once_flag once;
static tss_t key;
static int entered;
static int once_count;
static int destructor_count;
static thrd_t worker_thread;
static int main_value;
static int worker_value;

static void once_initializer(void)
{
    once_count++;
}

static void tss_destructor(void *value)
{
    if (value == &worker_value)
        destructor_count++;
}

static int worker(void *argument)
{
    (void)argument;

    worker_thread = thrd_current();
    if (thrd_equal(worker_thread, thrd_current()) == 0)
        thrd_exit(41);
    if (tss_set(key, &worker_value) != thrd_success ||
        tss_get(key) != &worker_value)
        thrd_exit(42);

    call_once(&once, once_initializer);
    if (mtx_lock(&mutex) != thrd_success)
        thrd_exit(43);
    entered = 1;
    if (cnd_signal(&condition) != thrd_success) {
        mtx_unlock(&mutex);
        thrd_exit(44);
    }
    mtx_unlock(&mutex);

    thrd_yield();
    thrd_exit(37);
}

int main(void)
{
    thrd_t thread;
    int result = -1;
    struct timespec zero = { 0, 0 };
    int ok = 1;

    once = 0;
    if (mtx_init(&mutex, mtx_plain | mtx_timed) != thrd_success)
        ok = 0;
    if (cnd_init(&condition) != thrd_success)
        ok = 0;
    if (tss_create(&key, tss_destructor) != thrd_success)
        ok = 0;
    if (tss_set(key, &main_value) != thrd_success ||
        tss_get(key) != &main_value)
        ok = 0;

    call_once(&once, once_initializer);
    if (once_count != 1)
        ok = 0;

    if (mtx_lock(&mutex) != thrd_success)
        ok = 0;
    if (mtx_trylock(&mutex) != thrd_busy)
        ok = 0;
    if (thrd_create(&thread, worker, 0) != thrd_success)
        ok = 0;
    while (!entered) {
        if (cnd_wait(&condition, &mutex) != thrd_success) {
            ok = 0;
            break;
        }
    }
    if (mtx_unlock(&mutex) != thrd_success)
        ok = 0;

    if (thrd_join(thread, &result) != thrd_success || result != 37)
        ok = 0;
    if (thrd_equal(thrd_current(), worker_thread) != 0)
        ok = 0;
    if (thrd_sleep(&zero, 0) != 0)
        ok = 0;

    /* An already-expired absolute deadline exercises thrd_timedout mapping. */
    if (mtx_lock(&mutex) != thrd_success)
        ok = 0;
    if (mtx_timedlock(&mutex, &zero) != thrd_timedout)
        ok = 0;
    if (mtx_unlock(&mutex) != thrd_success)
        ok = 0;

    if (destructor_count != 1)
        ok = 0;
    if (once_count != 1)
        ok = 0;

    tss_delete(key);
    cnd_destroy(&condition);
    mtx_destroy(&mutex);
    if (ok)
        puts("c-abi c11 threads ok");
    return ok ? 0 : 1;
}
