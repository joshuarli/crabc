#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <link.h>
#include <sys/auxv.h>
#include <stdlib.h>
#include <dlfcn.h>

#ifdef CLI_LIBRARY
int cli_value(void) { return CLI_LIBRARY; }
int cli_global = 13;
__attribute__((constructor)) static void constructor(void) { puts("dependency initialized"); }
#else
extern int cli_value(void);
extern int cli_global;
__attribute__((constructor)) static void constructor(void) { puts("application initialized"); }
#ifdef CLI_CHECK_AUXV
static int check_main(struct dl_phdr_info *info, size_t size, void *state)
{
    (void)size;
    if (*(int *)state) return 1;
    if ((unsigned long)info->dlpi_phdr != getauxval(AT_PHDR)
        || info->dlpi_phnum != getauxval(AT_PHNUM)
        || getauxval(AT_PHENT) != sizeof(ElfW(Phdr))
        || !getauxval(AT_BASE) || !getauxval(AT_ENTRY)) return 2;
    unsigned long entry = getauxval(AT_ENTRY);
    int executable = 0;
    for (unsigned index = 0; index < info->dlpi_phnum; ++index) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[index];
        unsigned long start = info->dlpi_addr + phdr->p_vaddr;
        if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_X)
            && entry >= start && entry - start < phdr->p_memsz) executable = 1;
    }
    if (!executable) return 2;
    *(int *)state = 1;
    return 1;
}
#endif
static _Thread_local int thread_value = 41;
static void *worker(void *unused)
{
    (void)unused;
    if (thread_value != 41) return (void *)1;
    thread_value = 73;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "argument") != 0)
        return 31;
    if (cli_global != 13) return 33;
    if (!getenv("CLI_ENV") || strcmp(getenv("CLI_ENV"), "preserved")) return 35;
    void *main_handle = dlopen(0, RTLD_NOW);
    if (!main_handle || dlsym(main_handle, "cli_global") != &cli_global
        || dlclose(main_handle)) return 37;
#ifdef CLI_CHECK_AUXV
    int checked = 0;
    if (dl_iterate_phdr(check_main, &checked) != 1 || checked != 1) return 34;
    const char *execfn = (const char *)getauxval(AT_EXECFN);
    if (!execfn || (strcmp(execfn, "/consumer") && strcmp(execfn, "/system")
        && strcmp(execfn, "./--consumer"))) return 36;
#endif
    pthread_t thread;
    void *result;
    if (pthread_create(&thread, 0, worker, 0) || pthread_join(thread, &result)
        || result || thread_value != 41) return 32;
    printf("direct interpreter application entered: %s %d\n", argv[0], cli_value());
    return 0;
}
#endif
