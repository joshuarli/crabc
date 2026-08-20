#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* These are musl's internal stage signatures; no public header declares them. */
typedef void (*loader_stage_fn)(size_t *, size_t *);

extern unsigned long getauxval(unsigned long);
extern char *program_invocation_name;

enum {
    AT_PAGESZ = 6,
    AT_SECURE = 23,
};

static int run_stage(loader_stage_fn stage,
                     const char *argv0,
                     const char *env_entry,
                     unsigned long page_size)
{
    size_t stack[] = {
        1,
        (size_t)argv0,
        0,
        (size_t)env_entry,
        0,
    };
    size_t auxv[] = {
        AT_PAGESZ, page_size,
        AT_SECURE, 0,
        0, 0,
    };

    stage(stack, auxv);
    if (getauxval(AT_PAGESZ) != page_size)
        return 1;
    if (getauxval(AT_SECURE) != 0)
        return 2;
    if (getenv("CRABC_LOADER_STAGE") == NULL ||
        strcmp(getenv("CRABC_LOADER_STAGE"), env_entry + 19) != 0)
        return 3;
    if (program_invocation_name == NULL || strcmp(program_invocation_name, argv0) != 0)
        return 4;
    return 0;
}

int main(void)
{
    void *libc = dlopen("libc.so", RTLD_NOW);
    if (libc == NULL)
        return 9;
    loader_stage_fn dls2b = (loader_stage_fn)dlsym(libc, "__dls2b");
    loader_stage_fn dls3 = (loader_stage_fn)dlsym(libc, "__dls3");
    if (dls2b == NULL || dls3 == NULL)
        return 10;

    /* __dls2b must dispatch through the libc-visible stage-3 boundary. */
    const char first_env[] = "CRABC_LOADER_STAGE=stage2b";
    int rc = run_stage(dls2b, "m4-loader-stage-2b", first_env, 4096);
    if (rc != 0)
        return 10 + rc;

    /* A direct __dls3 call updates the same startup state for a later vector. */
    const char second_env[] = "CRABC_LOADER_STAGE=stage3";
    rc = run_stage(dls3, "m4-loader-stage-3", second_env, 8192);
    if (rc != 0)
        return 20 + rc;

    dlclose(libc);
    puts("m4 loader startup ok");
    return 0;
}
