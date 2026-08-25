/* Main executable fixture; it owns the executable side of lifecycle proof. */
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>

#include "lifecycle_trace.h"

int lifecycle_mid_value(void);

static __thread int lifecycle_main_tls = 13;

static void lifecycle_preinit(void)
{
    lifecycle_require(lifecycle_main_tls == 13);
    lifecycle_trace('P');
}

/* The ELF main executable is the only object allowed to carry preinit. */
__attribute__((section(".preinit_array"), used))
static void (*const lifecycle_preinit_slot)(void) = lifecycle_preinit;

/*
 * `crti.o` opens .init/.fini and `crtn.o` closes it.  These fixture-only
 * fragments intentionally contain no return: execution falls through to the
 * crtn epilogue, proving the conventional split-object link order without
 * adding any production assembly source.
 */
void lifecycle_legacy_init(void)
{
    lifecycle_trace('I');
}

void lifecycle_legacy_fini(void)
{
    lifecycle_trace('F');
}

__asm__(
    ".pushsection .init,\"ax\",@progbits\n"
    "bl lifecycle_legacy_init\n"
    ".popsection\n"
    ".pushsection .fini,\"ax\",@progbits\n"
    "bl lifecycle_legacy_fini\n"
    ".popsection\n");

__attribute__((constructor(101))) static void lifecycle_constructor_early(void)
{
    void *allocation;

    lifecycle_require(lifecycle_main_tls == 13);
    allocation = malloc(32);
    lifecycle_require(allocation != NULL);
    free(allocation);
    lifecycle_trace('A');
}

__attribute__((constructor(65534))) static void lifecycle_constructor_late(void)
{
    lifecycle_trace('B');
}

__attribute__((destructor(101))) static void lifecycle_destructor_early(void)
{
    lifecycle_trace('a');
}

__attribute__((destructor(65534))) static void lifecycle_destructor_late(void)
{
    lifecycle_trace('b');
}

static void lifecycle_atexit_first(void)
{
    lifecycle_trace('1');
}

static void lifecycle_atexit_second(void)
{
    lifecycle_trace('2');
}

int main(void)
{
    void *handle;
    void *tls_handle;
    int (*value)(void);

    lifecycle_require(lifecycle_main_tls == 13);
    lifecycle_require(lifecycle_mid_value() == 11);
    lifecycle_trace('N');
    lifecycle_require(atexit(lifecycle_atexit_first) == 0);
    lifecycle_require(atexit(lifecycle_atexit_second) == 0);

    handle = dlopen("liblifecycle_late.so", RTLD_NOW | RTLD_LOCAL);
    lifecycle_require(handle != NULL);
    value = (int (*)(void))dlsym(handle, "lifecycle_late_value");
    lifecycle_require(value != NULL && value() == 17);
    tls_handle = dlopen("liblifecycle_late_tls.so", RTLD_NOW | RTLD_LOCAL);
    lifecycle_require(tls_handle != NULL);
    value = (int (*)(void))dlsym(tls_handle, "lifecycle_late_tls_value");
    lifecycle_require(value != NULL && value() == 19);
    if (getenv("CRABC_LIFECYCLE_MAPS_WAIT") != NULL) {
        char release;

        lifecycle_require(write(1, "maps-ready\n", sizeof("maps-ready\n") - 1) == sizeof("maps-ready\n") - 1);
        lifecycle_require(read(0, &release, 1) == 1);
    }
    lifecycle_require(dlclose(handle) == 0);

    /* musl retains the finalized mapping; reopen must not duplicate hooks. */
    handle = dlopen("liblifecycle_late.so", RTLD_NOW | RTLD_LOCAL);
    lifecycle_require(handle != NULL);
    value = (int (*)(void))dlsym(handle, "lifecycle_late_value");
    lifecycle_require(value != NULL && value() == 17);
    lifecycle_require(dlclose(handle) == 0);
    lifecycle_require(dlclose(tls_handle) == 0);
    return 0;
}
