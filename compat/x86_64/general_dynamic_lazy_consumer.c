#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static _Atomic int ready;
static int (*worker_run)(void);
static void *worker(void *unused)
{
    (void)unused;
    while (!atomic_load_explicit(&ready, memory_order_acquire)) {}
    return (void *)(uintptr_t)(worker_run() != 73);
}

static int count_object(struct dl_phdr_info *info, size_t bytes, void *count)
{
    (void)info; (void)bytes;
    ++*(int *)count;
    return 0;
}

static uintptr_t *pending_slot(void *handle, const char *name)
{
    struct link_map *map = 0;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) || !map) return 0;
    Elf64_Sym *symbols = 0;
    const char *strings = 0;
    Elf64_Rela *tables[2] = {0};
    size_t sizes[2] = {0};
    for (Elf64_Dyn *dynamic = map->l_ld; dynamic->d_tag; ++dynamic) {
        uintptr_t address = map->l_addr + dynamic->d_un.d_ptr;
        if (dynamic->d_tag == DT_SYMTAB) symbols = (void *)address;
        if (dynamic->d_tag == DT_STRTAB) strings = (void *)address;
        if (dynamic->d_tag == DT_RELA) tables[0] = (void *)address;
        if (dynamic->d_tag == DT_JMPREL) tables[1] = (void *)address;
        if (dynamic->d_tag == DT_RELASZ) sizes[0] = dynamic->d_un.d_val;
        if (dynamic->d_tag == DT_PLTRELSZ) sizes[1] = dynamic->d_un.d_val;
    }
    if (!symbols || !strings) return 0;
    for (int table = 0; table != 2; ++table) {
        for (size_t index = 0; index < sizes[table] / sizeof(Elf64_Rela); ++index) {
            Elf64_Rela *relocation = &tables[table][index];
            unsigned type = ELF64_R_TYPE(relocation->r_info);
            if ((type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT)
                && !strcmp(strings + symbols[ELF64_R_SYM(relocation->r_info)].st_name, name))
                return (void *)(map->l_addr + relocation->r_offset);
        }
    }
    return 0;
}

/* Harness-only raw address-space clone: the child calls no libc state owner,
 * allocator, pthread or loader. This is a protection proof, not dynamic fork
 * qualification. It runs only after the selected worker has joined. */
static int read_only(uintptr_t *slot)
{
    long child = syscall(SYS_fork);
    if (!child) {
        *(volatile uintptr_t *)slot = 0;
        syscall(SYS_exit, 90);
        for (;;) {}
    }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child
        && WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 1;
    int got = !strcmp(argv[2], "got");
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, 0)) return 7;
    if (dlopen(argv[1], RTLD_NOW)) return 8;
    if (!dlerror()) return 9;
    void *plugin = dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    if (!plugin) { puts(dlerror()); return 2; }
    int (*run)(void) = (int (*)(void))dlsym(plugin, "deferred_run");
    if (!run) return 3;
    uintptr_t *slot = pending_slot(plugin, got ? "deferred_value" : "deferred_function");
    if (!slot) return 10;
    uintptr_t original = *slot;
    int before = 0, after = 0;
    dl_iterate_phdr(count_object, &before);
    if (dlopen("libdeferred-bad.so", RTLD_LAZY | RTLD_GLOBAL)) return 11;
    if (!dlerror()) return 12;
    dl_iterate_phdr(count_object, &after);
    if (before != after || *slot != original) return 13;
    if (dlsym(RTLD_DEFAULT, "deferred_function")) return 14;
    (void)dlerror();
    void *provider = dlopen("libdeferred-provider.so", RTLD_NOW | RTLD_LOCAL);
    if (!provider) { puts(dlerror()); return 4; }
    if (*slot != original) return 15;
    if (dlopen("libdeferred-provider.so", RTLD_NOW | RTLD_NOLOAD | RTLD_GLOBAL) != provider) return 16;
    if (run() != 73) return 5;
    worker_run = run;
    atomic_store_explicit(&ready, 1, memory_order_release);
    void *result = 0;
    if (pthread_join(thread, &result) || result) return 17;
    if (got && !read_only(slot)) return 18;
    if (dlclose(plugin) || dlclose(provider)) return 6;
    puts("deferred binding: retained PLT/GOT resolves after global provider");
    return 0;
}
