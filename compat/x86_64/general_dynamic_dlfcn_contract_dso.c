/* Variants for general_dynamic_dlfcn_contract.c; one -D selects the object.
 * BASE: shared by the initial and runtime graphs. INIT: initial dependency
 * of main. RT/RTDEP: runtime-new closure. MISSING needs an absent object;
 * UNRESOLVED needs a symbol its installed provider lacks; INITIAL_EXEC uses
 * initial-exec TLS from a runtime module; PROVIDER is the dependency stub.
 * FR_ROOT -> {FR_TLS, FR_LATE} is the failed-load rollback graph of
 * general_dynamic_dlfcn_contract_rollback.c; CC_OK with INDEX is one of the
 * concurrent successes of general_dynamic_dlfcn_contract_concurrent.c.
 * RE_ROOT -> RE_DEP, RE_PLAIN and RE_SHARED_FAIL -> {RE_DEP, missing} are
 * general_dynamic_dlfcn_contract_reentrant.c constructor reentry objects.
 * FK_CTOR forks from its constructor for general_dynamic_dlfcn_contract_fork.c.
 * RELR_DSO carries packed-relative relocations for ..._relr.py. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
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
#elif defined(FR_TLS)
/* Failed-load rollback: the TLS dependency admitted before a later failure. */
__thread int fr_tls_value = 7;
int *fr_tls_address(void) { return &fr_tls_value; }
__attribute__((constructor)) static void fr_tls_construct(void)
{
    printf("constructor libfr_tls.so tls=%d\n", fr_tls_value);
}
#elif defined(FR_LATE)
#ifndef OMIT_PROVIDED
int fr_late_provided = 5;
#endif
int fr_late_marker = 6;
__attribute__((constructor)) static void fr_late_construct(void)
{
    printf("constructor libfr_late.so\n");
}
#elif defined(FR_ROOT)
extern int fr_late_provided;
int *fr_tls_address(void);
int fr_root_value(void) { return fr_late_provided * 100 + *fr_tls_address(); }
__attribute__((constructor)) static void fr_root_construct(void)
{
    printf("constructor libfr_root.so value=%d\n", fr_root_value());
}
#elif defined(CC_OK)
/* Concurrent successful loads; odd indices add a TLS module. */
#define CC_NAME2(prefix, index) prefix##index
#define CC_NAME(prefix, index) CC_NAME2(prefix, index)
int CC_NAME(cc_ok_value, INDEX) = 900 + INDEX;
#if INDEX % 2
__thread int CC_NAME(cc_ok_tls, INDEX) = 800 + INDEX;
int CC_NAME(cc_ok_tls_read, INDEX)(void) { return CC_NAME(cc_ok_tls, INDEX); }
#endif
#elif defined(FK_CTOR)
/* Forks from its own constructor; the child loads, fails and reopens. */
#include <sys/wait.h>
#include <unistd.h>
#include "general_dynamic_dlfcn_contract.h"
int fk_ctor_value = 61;
__attribute__((constructor)) static void fk_ctor_construct(void)
{
    printf("fork constructor begin\n");
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        printf("child failed open: %s\n", result(dlopen("libfr_root.so", RTLD_NOW | RTLD_GLOBAL)));
        show_error("child failed open");
        printf("child NOLOAD rolled-back tls: %s\n", result(dlopen("libfr_tls.so", RTLD_NOW | RTLD_NOLOAD)));
        show_error("child NOLOAD rolled-back tls");
        void *self = dlopen("libfk_ctor.so", RTLD_NOW | RTLD_NOLOAD);
        printf("child NOLOAD constructing self: %s\n", result(self));
        int *value = self ? dlsym(self, "fk_ctor_value") : 0;
        printf("child self value=%d\n", value ? *value : -1);
        void *success = dlopen("libcc_ok3.so", RTLD_NOW);
        int (*read)(void) = success ? (int (*)(void))dlsym(success, "cc_ok_tls_read3") : 0;
        printf("child new load: %s tls=%d\n", result(success), read ? read() : -1);
        fflush(stdout);
        _exit(0);
    }
    int status = -1;
    waitpid(child, &status, 0);
    printf("fork constructor end: child exited=%d status=%d\n", WIFEXITED(status), WEXITSTATUS(status));
}
#elif defined(RE_DEP)
/* Reentrant constructors: libre_root.so needs this object, whose constructor
 * reopens the root while the root itself is still unconstructed. */
static int re_image(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size; (void)data;
    const char *name = info->dlpi_name ? strrchr(info->dlpi_name, '/') : 0;
    if (name && !strncmp(name, "/libre_", 7)) printf("  dep constructor sees %s\n", name + 1);
    return 0;
}
__attribute__((constructor)) static void re_dep_construct(void)
{
    printf("dep constructor begin\n");
    dl_iterate_phdr(re_image, 0);
    void *root = dlopen("libre_root.so", RTLD_NOW | RTLD_NOLOAD);
    printf("dep constructor NOLOAD root: %s\n", root ? "handle" : "null");
    printf("dep constructor end\n");
}
#elif defined(RE_ROOT)
#include "general_dynamic_dlfcn_contract.h"
int re_root_symbol = 71;
static int re_count(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    if (info->dlpi_name && strstr(info->dlpi_name, "libre_")) ++*(int *)data;
    return 0;
}
__attribute__((constructor)) static void re_root_construct(void)
{
    const char *error = dlerror();
    printf("root constructor begin; caller pending: %s\n", error ? error : "(none)");
    void *self = dlopen("libre_root.so", RTLD_NOW | RTLD_NOLOAD);
    printf("root constructor NOLOAD self: %s\n", self ? "handle" : "null");
    printf("root constructor dlsym self handle: %s\n", self && dlsym(self, "re_root_symbol") ? "found" : "null");
    printf("root constructor dlsym default: %s\n", dlsym(RTLD_DEFAULT, "re_root_symbol") ? "found" : "null");
    error = dlerror();
    printf("root constructor dlerror: %s\n", error ? error : "(none)");
    printf("root constructor dlclose self: %d\n", self ? dlclose(self) : -1);
    void *plain = dlopen("libre_plain.so", RTLD_NOW | RTLD_LOCAL);
    printf("root constructor nested open: %s\n", plain ? "handle" : "null");
    int *value = plain ? dlsym(plain, "dc_plain_value") : 0;
    printf("root constructor nested value: %d\n", value ? *value : -1);
    /* A nested failure sharing the published, still-constructing dependency
     * rolls back only its own new objects. */
    int before = 0, after = 0;
    dl_iterate_phdr(re_count, &before);
    printf("root constructor shared failure: %s\n", result(dlopen("libre_sharedfail.so", RTLD_NOW)));
    show_error("root constructor shared failure");
    dl_iterate_phdr(re_count, &after);
    printf("root constructor images before=%d after=%d\n", before, after);
    printf("root constructor dep after failure: %s\n", result(dlopen("libre_dep.so", RTLD_NOW | RTLD_NOLOAD)));
    /* Leave this failure pending for the dlopen caller. */
    printf("root constructor missing open: %s\n", dlopen("libre_missing.so", RTLD_NOW) ? "handle" : "null");
    printf("root constructor end\n");
}
#elif defined(RE_SHARED_FAIL)
int re_shared_fail_marker = 91;
#elif defined(RE_PLAIN)
int dc_plain_value = 81;
__attribute__((constructor)) static void re_plain_construct(void)
{
    printf("plain constructor; pending: %s\n", dlerror() ? "yes" : "(none)");
}
#elif defined(RELR_DSO)
/* Seventy pointers into this object (crossing one 63-word RELR bitmap),
 * a separated cluster, and one symbolic data import that stays in RELA. */
extern char **environ;
static int relr_targets[80];
int *relr_table[70] = {
#define RELR_TEN(base) &relr_targets[base], &relr_targets[base + 1], &relr_targets[base + 2], \
    &relr_targets[base + 3], &relr_targets[base + 4], &relr_targets[base + 5], &relr_targets[base + 6], \
    &relr_targets[base + 7], &relr_targets[base + 8], &relr_targets[base + 9]
    RELR_TEN(0), RELR_TEN(10), RELR_TEN(20), RELR_TEN(30), RELR_TEN(40), RELR_TEN(50), RELR_TEN(60),
};
static char relr_gap[4096] = {1};
int *relr_far[3] = { &relr_targets[70], &relr_targets[75], &relr_targets[79] };
char ***relr_environ = &environ;
int relr_matches(void)
{
    int matches = relr_gap[0] - 1;
    for (int index = 0; index < 70; ++index) matches += relr_table[index] == &relr_targets[index];
    matches += relr_far[0] == &relr_targets[70] && relr_far[1] == &relr_targets[75] && relr_far[2] == &relr_targets[79];
    return matches;
}
#elif defined(PLAIN)
int dc_plain_value = 80;
int dc_plain_function(void) { return dc_plain_value; }
#else
#error "select one general_dynamic_dlfcn_contract_dso variant"
#endif
