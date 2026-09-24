/* Owned static product process-termination consumer.
 *
 * Each invocation selects one termination route through argv[1] after the
 * same constructor, stdio, atexit, and at_quick_exit state is established:
 *
 *   return, exit             ordinary exit from main
 *   worker-exit              exit() called by a pthread worker while main joins
 *   main-pthread-exit        the last live task is a worker after main's
 *                            pthread_exit(), so its return performs exit(0)
 *   _Exit, _exit             immediate termination
 *   quick_exit               at_quick_exit handlers only
 *   abort, abort-handled     SIGABRT, including a returning SIGABRT handler
 *   signal                   default-action SIGTERM
 *
 * Ordering markers use write(2) directly. Newline-free pending stdout text
 * (musl line-buffers until its first write discovers a non-terminal) and the
 * fully buffered FILE in argv[2] observe whether termination flushed stdio.
 * The runner records each exit status plus both byte streams, then compares
 * the complete transcript with pinned musl. No route writes an address or
 * timing value.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "owned static termination requires native Linux/x86-64 LP64"
#endif

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void mark(const char *text)
{
    size_t length = strlen(text);

    if (write(1, text, length) != (ssize_t)length)
        _exit(90);
}

__attribute__((constructor))
static void constructed(void)
{
    mark("C");
}

__attribute__((destructor))
static void destructed(void)
{
    mark("D");
}

static void first_atexit(void) { mark("1"); }
static void second_atexit(void) { mark("2"); }
static void first_quick_exit(void) { mark("q"); }
static void second_quick_exit(void) { mark("Q"); }

static void returning_abort_handler(int signal_number)
{
    if (signal_number == SIGABRT)
        mark("H");
}

static void *exiting_worker(void *unused)
{
    (void)unused;
    mark("W");
    exit(11);
}

static void *last_worker(void *unused)
{
    const struct timespec delay = { 0, 50 * 1000 * 1000 };

    (void)unused;
    /* Main has already published "M" and is about to leave through
     * pthread_exit; returning from the final task is ordinary exit(0). */
    nanosleep(&delay, NULL);
    mark("w");
    return NULL;
}

int main(int argc, char **argv)
{
    FILE *stream;
    pthread_t worker;
    const char *route;

    if (argc != 3)
        return 120;
    route = argv[1];
    stream = fopen(argv[2], "w");
    if (stream == NULL || setvbuf(stream, NULL, _IOFBF, BUFSIZ) != 0)
        return 121;
    if (fputs("file-buffered\n", stream) == EOF || fputs("stdout-pending", stdout) == EOF)
        return 122;
    if (atexit(first_atexit) != 0 || atexit(second_atexit) != 0)
        return 123;
    if (at_quick_exit(first_quick_exit) != 0 || at_quick_exit(second_quick_exit) != 0)
        return 124;
    mark("M");

    if (strcmp(route, "return") == 0)
        return 7;
    if (strcmp(route, "exit") == 0)
        exit(9);
    if (strcmp(route, "worker-exit") == 0) {
        if (pthread_create(&worker, NULL, exiting_worker, NULL) != 0)
            return 125;
        pthread_join(worker, NULL);
        return 126;
    }
    if (strcmp(route, "main-pthread-exit") == 0) {
        if (pthread_create(&worker, NULL, last_worker, NULL) != 0 ||
            pthread_detach(worker) != 0)
            return 127;
        pthread_exit(NULL);
    }
    if (strcmp(route, "_Exit") == 0)
        _Exit(13);
    if (strcmp(route, "_exit") == 0)
        _exit(14);
    if (strcmp(route, "quick_exit") == 0)
        quick_exit(15);
    if (strcmp(route, "abort") == 0)
        abort();
    if (strcmp(route, "abort-handled") == 0) {
        if (signal(SIGABRT, returning_abort_handler) == SIG_ERR)
            return 128;
        abort();
    }
    if (strcmp(route, "signal") == 0) {
        raise(SIGTERM);
        return 129;
    }
    return 119;
}
