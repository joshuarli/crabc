#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void pthread_exit_expect(int);
void pthread_exit_tls_prepare(int);
void pthread_exit_tls_finish(int);
void pthread_exit_ordinary(void);
void pthread_exit_executable_fini(void);

enum { SIMULTANEOUS_WORKERS = 8 };
struct thread_record { int value; atomic_int cleanup; atomic_int ready; };
static struct thread_record initial = { 101 };
static struct thread_record workers[SIMULTANEOUS_WORKERS];
static pthread_key_t key;
static pthread_t initial_thread;
static int count;
static int cancel_initial;
static int cancel_worker;
static int orphan_only;
static int channel[2];
static FILE *orphaned;
static char orphaned_buffer[128];
static atomic_int arrived;

static void require(int condition)
{
    if (!condition)
        _Exit(90);
}

static void cleanup(void *opaque)
{
    struct thread_record *record = opaque;
    require(atomic_exchange(&record->cleanup, 1) == 0);
    if (!orphan_only && (record == &initial ? !cancel_worker : cancel_worker))
        funlockfile(orphaned);
}

static void destroy_value(void *opaque)
{
    struct thread_record *record = opaque;
    require(atomic_load(&record->cleanup) == 1);
    pthread_exit_tls_finish(record->value);
}

static void executable_fini(void) __attribute__((destructor));
static void executable_fini(void) { pthread_exit_executable_fini(); }

static void *worker(void *opaque)
{
    struct thread_record *record = opaque;
    pthread_exit_tls_prepare(record->value);
    require(pthread_setspecific(key, record) == 0);
    pthread_cleanup_push(cleanup, record);
    if (cancel_worker) {
        /* Cleanup releases ordinary FILE ownership; separate orphan cases
         * deliberately retain it to test the source retirement sentinel. */
        flockfile(orphaned);
        require(fputs("cleanup FILE flush\n", orphaned) >= 0);
        atomic_store(&record->ready, 1);
        char byte;
        (void)read(channel[0], &byte, 1);
        _Exit(91);
    }
    if (cancel_initial)
        require(pthread_cancel(initial_thread) == 0);
    /* The external parent writes only after /proc reports the initial task
     * as a zombie. Waiting on ordinary stdin preserves a genuine installed
     * product boundary and requires no /proc mount inside its sealed root. */
    char release;
    require(read(STDIN_FILENO, &release, 1) == 1 && release == 'R');
    require(atomic_load(&initial.cleanup) == 1);
    if (orphan_only) {
        require(ftrylockfile(orphaned) != 0);
        const char message[] = "orphaned FILE remains locked\n";
        require(write(STDOUT_FILENO, message, sizeof message - 1) == sizeof message - 1);
        _Exit(0);
    }
    flockfile(orphaned);
    funlockfile(orphaned);
    atomic_fetch_add(&arrived, 1);
    while (atomic_load(&arrived) != count)
        sched_yield();
    if (record->value & 1)
        pthread_exit(NULL);
    pthread_cleanup_pop(1);
    return NULL;
}

int main(int argc, char **argv)
{
    require(argc == 2);
    if (!strcmp(argv[1], "single")) {
        count = 0;
    } else if (!strcmp(argv[1], "simultaneous")) {
        count = SIMULTANEOUS_WORKERS;
    } else if (!strcmp(argv[1], "cancel-main")) {
        count = 1;
        cancel_initial = 1;
    } else if (!strcmp(argv[1], "cancel-worker")) {
        count = 1;
        cancel_worker = 1;
    } else if (!strcmp(argv[1], "orphan-main")) {
        count = 1;
        orphan_only = 1;
    } else if (!strcmp(argv[1], "orphan-worker")) {
        count = 1;
        cancel_worker = 1;
        orphan_only = 1;
    } else {
        _Exit(92);
    }
    alarm(10);
    require(pipe(channel) == 0);
    orphaned = fdopen(STDERR_FILENO, "w");
    require(orphaned != NULL);
    require(setvbuf(orphaned, orphaned_buffer, _IOFBF, sizeof orphaned_buffer) == 0);
    require(pthread_key_create(&key, destroy_value) == 0);
    require(atexit(pthread_exit_ordinary) == 0);
    pthread_exit_expect(count + 1);
    initial_thread = pthread_self();
    pthread_exit_tls_prepare(initial.value);
    require(pthread_setspecific(key, &initial) == 0);
    pthread_cleanup_push(cleanup, &initial);
    /* Ordinary cleanup unlocks before TSD; orphan-only cases retain it. */
    if (!cancel_worker) {
        flockfile(orphaned);
        require(fputs("cleanup FILE flush\n", orphaned) >= 0);
    }
    for (int index = 0; index < count; ++index) {
        pthread_t thread;
        workers[index].value = 200 + index;
        require(pthread_create(&thread, NULL, worker, &workers[index]) == 0);
        if (cancel_worker) {
            while (!atomic_load(&workers[index].ready))
                sched_yield();
            require(pthread_cancel(thread) == 0);
            void *result = NULL;
            require(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
            if (orphan_only) {
                require(ftrylockfile(orphaned) != 0);
                const char message[] = "orphaned FILE remains locked\n";
                require(write(STDOUT_FILENO, message, sizeof message - 1) == sizeof message - 1);
                _Exit(0);
            }
            require(ftrylockfile(orphaned) == 0);
            funlockfile(orphaned);
        }
    }
    if (cancel_initial) {
        char byte;
        (void)read(channel[0], &byte, 1);
        _Exit(93);
    }
    pthread_exit(NULL);
    pthread_cleanup_pop(0);
}
