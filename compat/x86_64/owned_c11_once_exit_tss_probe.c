#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>
static once_flag flag = ONCE_FLAG_INIT;
static tss_t key;
static int attempts, destroyed;
static void initialize(void) { if (++attempts == 1) thrd_exit(INT_MIN); }
static void destructor(void *value)
{
    if (value != &flag || attempts != 1) _Exit(1);
    /* Thread exit must undo the abandoned initializer before TSS runs.
     * Otherwise this destructor waits for its own prior initializer. */
    call_once(&flag, initialize);
    if (attempts != 2) _Exit(2);
    destroyed = 1;
}
static int worker(void *unused)
{
    (void)unused;
    if (tss_set(key, &flag) != thrd_success) _Exit(3);
    call_once(&flag, initialize);
    _Exit(4);
}
int main(void)
{
    thrd_t thread; int result;
    if (tss_create(&key, destructor) != thrd_success ||
        thrd_create(&thread, worker, NULL) != thrd_success ||
        thrd_join(thread, &result) != thrd_success ||
        result != INT_MIN || !destroyed || attempts != 2) return 5;
    tss_delete(key);
    puts("c11 once exit TSS retry: PASS");
    return 0;
}
