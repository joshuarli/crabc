#ifndef LOADER110_SOURCE_PROBE
#define _GNU_SOURCE
#include <dlfcn.h>
#else
struct loader110_address_info {
    const char *name;
    void *base;
    const char *symbol_name;
    void *symbol_address;
};
struct loader110_diagnostic { int kind, number; void *text; unsigned long text_len; };
extern int __crabc_x86_64_runtime_address(unsigned long, struct loader110_address_info *);
extern void *__crabc_x86_64_runtime_open(const char *, int, struct loader110_diagnostic *);
#endif

extern int loader110_first_anchor(void);
extern int loader110_last_anchor(void);
int loader110_constructor_calls;
int loader110_constructor_reentry;

__attribute__((constructor)) static void loader110_initialize(void)
{
    ++loader110_constructor_calls;
#ifndef LOADER110_SOURCE_PROBE
    Dl_info info;
    if (dladdr(&loader110_constructor_calls, &info)) {
        void *self = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
        loader110_constructor_reentry = self != 0;
    }
#else
    struct loader110_address_info info = {0};
    struct loader110_diagnostic diagnostic = {0};
    if (__crabc_x86_64_runtime_address((unsigned long)&loader110_constructor_calls, &info)) {
        void *self = __crabc_x86_64_runtime_open(info.name, 2 | 4, &diagnostic);
        loader110_constructor_reentry = self != 0 && diagnostic.kind == 0;
    }
#endif
}

int loader110_next_from_caller(void)
{
    int anchors = loader110_first_anchor() + loader110_last_anchor();
#ifndef LOADER110_SOURCE_PROBE
    int *value = dlsym(RTLD_NEXT, "loader110_next_value");
    return value && anchors == 3 ? *value : -1;
#else
    return anchors;
#endif
}
