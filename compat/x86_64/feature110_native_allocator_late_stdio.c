#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef FEATURE110_MUSL_ORACLE
extern int __crabc_x86_owned_allocator_lifecycle_test_phase(void);
#endif

#ifdef FEATURE110_INITIAL_DSO
extern int dynamic_native_allocator_dso_live(void);
#endif

static pthread_key_t key;
static unsigned char *constructor_client;
static unsigned char *worker_client;
static unsigned int worker_stage;
static char stream_buffer[128];

static void check_at(int yes, unsigned int line)
{
    if (yes) return;
    char digits[16];
    size_t index = sizeof(digits);
    digits[--index] = '\n';
    do {
        digits[--index] = (char)('0' + line % 10);
        line /= 10;
    } while (line != 0);
    (void)!write(2, digits + index, sizeof(digits) - index);
    _Exit(83);
}
#define check(yes) check_at((yes), __LINE__)
static void check_native_phase(int expected)
{
#ifndef FEATURE110_MUSL_ORACLE
    check(__crabc_x86_owned_allocator_lifecycle_test_phase() == expected);
#else
    // Musl provides the public lifetime oracle, without the private native
    // allocator's logical-finalization audit. Callback ordering is shared.
    (void)expected;
#endif
}

static void message(const char *text)
{
    size_t length = strlen(text);
    check(write(1, text, length) == (ssize_t)length);
}

static void callback_allocation(void)
{
    errno = EDOM;
    unsigned char *client = malloc(193);
    check(client != NULL && errno == EDOM);
    memset(client, 0x51, 193);
    client = realloc(client, 521);
    check(client != NULL && errno == EDOM && client[192] == 0x51);
    free(client);
    check(errno == EDOM);
}

__attribute__((constructor)) static void initialize(void)
{
    check_native_phase(1);
    constructor_client = malloc(257);
    check(constructor_client != NULL);
    memset(constructor_client, 0x39, 257);
    message("CTOR\n");
}

static void cleanup(void *argument)
{
    check(argument == worker_client && worker_stage == 0);
    callback_allocation();
    worker_stage = 1;
    message("CLEANUP\n");
}

static void destroy_value(void *argument)
{
    check(argument == worker_client && worker_stage == 1);
    callback_allocation();
    worker_stage = 2;
    message("TSD\n");
}

static void *worker(void *argument)
{
    (void)argument;
    worker_client = malloc(70000);
    check(worker_client != NULL);
    memset(worker_client, 0x6b, 70000);
    check(pthread_setspecific(key, worker_client) == 0);
    pthread_cleanup_push(cleanup, worker_client);
    pthread_cleanup_pop(1);
    return NULL;
}

static void registered_exit(void)
{
    check(worker_stage == 2);
    check_native_phase(1);
    callback_allocation();
    message("ATEXIT\n");
}

__attribute__((destructor)) static void finalize(void)
{
#ifdef FEATURE110_STATIC_FINI_AFTER_ALLOCATOR
    // The static executable walks its combined array in reverse link order;
    // the allocator entry precedes this application entry during teardown.
    check_native_phase(2);
#else
    // The dynamic main image finalizes before its libc dependency.
    check_native_phase(1);
#endif
    check(constructor_client[256] == 0x39);
    free(constructor_client);
    callback_allocation();
    message("FINI\n");
}

static ssize_t flush(void *cookie, const char *bytes, size_t length)
{
    (void)cookie;
    if (length == 0) return 0;
    check_native_phase(2);
    check(length == 8 && memcmp(bytes, "buffered", 8) == 0);
    check(worker_stage == 2 && worker_client != NULL);
    // The joined worker transferred this live allocation. Neither its
    // cleanup nor TSD callback consumed it; this callback consumes it once.
    check(worker_client[0] == 0x6b && worker_client[69999] == 0x6b);
    errno = ERANGE;
    free(worker_client);
    worker_client = NULL;
    check(errno == ERANGE);
    callback_allocation();
    message("FLUSH=2\n");
    return (ssize_t)length;
}

int main(void)
{
#ifdef FEATURE110_INITIAL_DSO
    check(dynamic_native_allocator_dso_live());
#endif
    check(constructor_client[256] == 0x39);
    check(pthread_key_create(&key, destroy_value) == 0);
    check(atexit(registered_exit) == 0);
    cookie_io_functions_t io = { .write = flush };
    FILE *stream = fopencookie(NULL, "w", io);
    check(stream != NULL);
    check(setvbuf(stream, stream_buffer, _IOFBF, sizeof(stream_buffer)) == 0);
    check(fwrite("buffered", 1, 8, stream) == 8);
    message("MAIN\n");
    pthread_t thread;
    void *result;
    check(pthread_create(&thread, NULL, worker, NULL) == 0);
    check(pthread_join(thread, &result) == 0 && result == NULL);
    check(worker_stage == 2 && worker_client != NULL);
    check(pthread_key_delete(key) == 0);
    return 0;
}
