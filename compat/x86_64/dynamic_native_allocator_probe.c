#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int __crabc_x86_owned_allocator_lifecycle_test_phase(void);
extern int dynamic_native_allocator_dso_live(void);
static _Atomic int ready;
static void *pending;
static char cookie_buffer[128];

static void check(int yes) { if (!yes) _Exit(82); }
static void message(const char *text) { size_t n = strlen(text); check(write(1, text, n) == (ssize_t)n); }
static void allocation(void)
{
    errno = EDOM;
    void *p = malloc(193);
    check(p != 0 && errno == EDOM);
    memset(p, 0x71, 193);
    p = realloc(p, 521);
    check(p != 0 && ((unsigned char *)p)[192] == 0x71);
    free(p);
}

__attribute__((constructor)) static void initialize(void)
{
    check(__crabc_x86_owned_allocator_lifecycle_test_phase() == 1);
    allocation();
    message("MAIN_INIT\n");
}

__attribute__((destructor)) static void finalize(void)
{
    check(__crabc_x86_owned_allocator_lifecycle_test_phase() == 1);
    allocation();
    message("MAIN_FINI\n");
}

static void registered_exit(void)
{
    check(__crabc_x86_owned_allocator_lifecycle_test_phase() == 1);
    allocation();
    free(pending);
    pending = 0;
    message("ATEXIT\n");
}

static ssize_t flush(void *cookie, const char *bytes, size_t length)
{
    (void)cookie;
    check(__crabc_x86_owned_allocator_lifecycle_test_phase() == 2);
    /* musl cookiewrite flushes buffered bytes, then the empty new span. */
    if (length == 0) return 0;
    check(length == 8 && memcmp(bytes, "buffered", 8) == 0);
    allocation();
    message("FLUSH=2\n");
    return (ssize_t)length;
}

static void *no_allocation(void *arg) { return arg; }
static void *allocate(void *arg)
{
    void *p = malloc(347);
    check(p != 0);
    memset(p, 0x45, 347);
    if (!arg) return p;
    pending = p;
    atomic_store_explicit(&ready, 1, memory_order_release);
    char release;
    check(read(0, &release, 1) == 1 && release == 'R');
    return 0;
}

int main(int argc, char **argv)
{
    (void)argv;
    check(dynamic_native_allocator_dso_live());
    check(atexit(registered_exit) == 0);
    cookie_io_functions_t io = { .write = flush };
    FILE *stream = fopencookie(0, "w", io);
    check(stream != 0);
    check(setvbuf(stream, cookie_buffer, _IOFBF, sizeof(cookie_buffer)) == 0);
    check(fwrite("buffered", 1, 8, stream) == 8);
    pthread_t thread;
    void *result;
    check(pthread_create(&thread, 0, no_allocation, (void *)37) == 0);
    check(pthread_join(thread, &result) == 0 && result == (void *)37);
    message("MAIN\n");
    if (argc > 1) {
        check(pthread_create(&thread, 0, allocate, (void *)1) == 0);
        while (!atomic_load_explicit(&ready, memory_order_acquire)) sched_yield();
        pthread_exit(0);
    }
    check(pthread_create(&thread, 0, allocate, 0) == 0);
    check(pthread_join(thread, &result) == 0);
    check(((unsigned char *)result)[346] == 0x45);
    free(result);
    return 0;
}
