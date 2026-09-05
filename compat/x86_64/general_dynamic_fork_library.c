/* The same real ELF TLS/callback provider is built as one initial DSO and
 * two runtime DSOs. The executable controls constructor fork/latch cases. */
#ifndef FORK_LIBRARY_TAG
#define FORK_LIBRARY_TAG 0
#endif
#include <stdlib.h>
#if FORK_LIBRARY_TAG == 0
static void (*constructor_hook)(int);
static void (*finalizer_hook)(int);
static int initial_ready;
void fork_constructor(int tag) {
    if (tag == 0) initial_ready = 1;
    else if (constructor_hook) constructor_hook(tag);
    else _Exit(80);
}
void fork_finalizer(int tag) {
    if (finalizer_hook) finalizer_hook(tag);
    else _Exit(81);
}
void fork_install_hooks(void (*initialize)(int), void (*finalize)(int)) {
    if (!initial_ready || constructor_hook || finalizer_hook) _Exit(82);
    constructor_hook = initialize;
    finalizer_hook = finalize;
    constructor_hook(0);
}
#else
extern void fork_constructor(int);
extern void fork_finalizer(int);
#endif
static _Thread_local _Alignas(64) int value = 31 + FORK_LIBRARY_TAG;
#if FORK_LIBRARY_TAG == 0
int *fork_initial_tls(void) { return &value; }
#else
int *fork_runtime_tls(void) { return &value; }
#endif
static void initialize(void) __attribute__((constructor));
static void initialize(void) { fork_constructor(FORK_LIBRARY_TAG); }
static void finalize(void) __attribute__((destructor));
static void finalize(void) { fork_finalizer(FORK_LIBRARY_TAG); }
