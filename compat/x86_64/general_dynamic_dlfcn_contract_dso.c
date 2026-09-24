/* Variants for general_dynamic_dlfcn_contract.c; one -D selects the object.
 * BASE: shared by the initial and runtime graphs. INIT: initial dependency
 * of main. RT/RTDEP: runtime-new closure. MISSING needs an absent object;
 * UNRESOLVED needs a symbol its installed provider lacks; INITIAL_EXEC uses
 * initial-exec TLS from a runtime module; PROVIDER is the dependency stub. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#if defined(BASE)
int dc_shared = 30;
int dc_base_only = 31;
int dc_weak = 32;
__thread int dc_base_tls = 33;
#elif defined(INIT)
int dc_shared = 20;
int dc_init_only = 21;
__attribute__((weak)) int dc_weak = 22;
int dc_init_next_shared(void)
{
    int *next = dlsym(RTLD_NEXT, "dc_shared");
    return next ? *next : -1;
}
#elif defined(RTDEP)
int dc_shared = 50;
int dc_rtdep_only = 51;
#elif defined(RT)
extern char _DYNAMIC[];
int dc_shared = 40;
int dc_rt_only = 41;
__thread int dc_rt_tls = 42;
int dc_rt_function(void) { return 43; }
__attribute__((visibility("hidden"))) int dc_rt_hidden = 44;
int dc_rt_sized[4] = {1, 2, 3, 4};
void *dc_rt_dynamic(void) { return _DYNAMIC; }
int *dc_rt_tls_address(void) { return &dc_rt_tls; }
/* Musl sets shutting_down before DSO destructors run. */
__attribute__((destructor)) static void dc_rt_finalize(void)
{
    void *late = dlopen("libdc_rtdep.so", RTLD_NOW);
    const char *error = dlerror();
    printf("destructor dlopen: %s; %s\n", late ? "handle" : "null", error ? error : "(none)");
    fflush(stdout);
}
#elif defined(PROVIDER)
#ifndef OMIT_PROVIDED
int dc_provided_value = 60;
#endif
int dc_provider_marker = 61;
#elif defined(MISSING) || defined(UNRESOLVED)
extern int dc_provided_value;
int dc_consumer_value(void) { return dc_provided_value; }
#elif defined(INITIAL_EXEC)
_Thread_local int dc_ie_tls __attribute__((tls_model("initial-exec"))) = 70;
int *dc_ie_address(void) { return &dc_ie_tls; }
#elif defined(PLAIN)
int dc_plain_value = 80;
int dc_plain_function(void) { return dc_plain_value; }
#else
#error "select one general_dynamic_dlfcn_contract_dso variant"
#endif
