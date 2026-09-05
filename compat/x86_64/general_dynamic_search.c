#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/auxv.h>
#ifdef SEARCH_PRELOAD
static _Thread_local int preload_tls = 3;
static int preload_starts;
__attribute__((constructor)) static void preload_start(void) {
    preload_starts++;
    preload_tls = 8;
    printf("preload-init=%d\n", preload_starts);
    fflush(stdout);
}
__attribute__((destructor)) static void preload_finish(void) {
    printf("preload-fini=%d\n", preload_starts);
}
#ifdef SEARCH_UNUSED_PRELOAD
int unused_search_value(void) { return preload_tls; }
#else
int search_value(void) { return preload_starts == 1 ? preload_tls : 0; }
#endif
#elif defined(SEARCH_UNRESOLVED_PRELOAD)
extern int unresolved_preload_import(void);
int search_value(void) { return unresolved_preload_import(); }
#elif defined(SEARCH_LEAF)
int search_value(void) { return SEARCH_LEAF; }
#elif defined(SEARCH_MIDDLE)
extern int search_value(void);
int search_result(void) { return search_value(); }
#elif defined(SEARCH_CALLER)
int search_result(void) {
    void *handle = dlopen("libsearch_mid.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle) return -1;
    int (*result)(void) = (int (*)(void))dlsym(handle, "search_result");
    return result ? result() : -2;
}
#else
#ifdef SEARCH_INITIAL
extern int search_result(void);
#endif
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    #ifdef SEARCH_SECURE
    if (getuid() != 65534 || geteuid() != 0 || getauxval(23) != 1) {
        printf("secure-context=%lu/%lu/%lu\n", (unsigned long)getuid(),
            (unsigned long)geteuid(), getauxval(23));
        return 6;
    }
    #endif
    #ifdef SEARCH_PATH_CACHE
    if (!dlopen("libcache_seed.so", RTLD_NOW | RTLD_LOCAL)) return 4;
    if (unlink("/etc/ld-musl-x86_64.path")) return 5;
    #endif
    #ifndef SEARCH_INITIAL
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { if (argv[2][0] == '0') { puts("search=0"); return 0; } puts(dlerror()); return 2; }
    int (*result)(void) = (int (*)(void))dlsym(handle, "search_result");
    if (!result) return 3;
    int value = result();
    #else
    int value = search_result();
    #endif
    printf("search=%d\n", value);
    return value != argv[2][0] - '0';
}
#endif
