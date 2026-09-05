/* Ordinary DSO TLS and finalization witness shared with pinned musl. */
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

static _Thread_local _Alignas(64) int thread_value = 31;
static atomic_int completed;
static int expected;
static int finalization_phase;
static int initialized;

static void initialize(void) __attribute__((constructor));
static void initialize(void) { initialized = 1; }

void pthread_exit_expect(int count) { expected = count; }

void pthread_exit_tls_prepare(int value)
{
    if (!initialized || thread_value != 31)
        _Exit(81);
    thread_value = value;
}

void pthread_exit_tls_finish(int value)
{
    if (thread_value != value)
        _Exit(82);
    atomic_fetch_add(&completed, 1);
}

void pthread_exit_ordinary(void)
{
    if (atomic_load(&completed) != expected || finalization_phase != 0)
        _Exit(83);
    finalization_phase = 1;
    puts("ordinary exit after pthread teardown");
}

void pthread_exit_executable_fini(void)
{
    if (finalization_phase != 1)
        _Exit(84);
    finalization_phase = 2;
    puts("executable fini");
}

static void finalize(void) __attribute__((destructor));
static void finalize(void)
{
    if (finalization_phase != 2)
        _Exit(85);
    puts("DSO fini");
}
