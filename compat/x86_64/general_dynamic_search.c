#include <dlfcn.h>
#include <stdio.h>
#ifdef SEARCH_LEAF
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
