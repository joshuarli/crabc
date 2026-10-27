#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef CRABC_DSO_PROBE
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

static int protected_before_main;

static int check_relro(uintptr_t base, const Elf64_Phdr *headers, unsigned long count)
{
    for (unsigned long i = 0; i < count; i++) {
        if (headers[i].p_type != PT_GNU_RELRO || !headers[i].p_memsz) continue;
        volatile unsigned char *target = (volatile unsigned char *)(base + headers[i].p_vaddr);
        pid_t child = fork();
        if (child == 0) {
            *target ^= 1;
            _exit(0);
        }
        if (child < 0) return 0;
        int status = 0;
        return waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV;
    }
    return 0;
}

#ifdef CRABC_DSO_PROBE
struct image_view {
    uintptr_t base;
    const Elf64_Phdr *headers;
    unsigned long count;
};

static int find_dso(struct dl_phdr_info *info, size_t size, void *context)
{
    (void)size;
    if (!strstr(info->dlpi_name, "hardened-relro-fixture.so")) return 0;
    struct image_view *image = context;
    image->base = info->dlpi_addr;
    image->headers = info->dlpi_phdr;
    image->count = info->dlpi_phnum;
    return 1;
}

static int count_dso(struct dl_phdr_info *info, size_t size, void *context)
{
    (void)info;
    (void)size;
    (*(unsigned long *)context)++;
    return 0;
}

struct syscall_filter_instruction {
    unsigned short code;
    unsigned char yes, no;
    unsigned int value;
};

struct syscall_filter_program {
    unsigned short length;
    struct syscall_filter_instruction *instructions;
};

static int failed_syscall_preserves_graph(int number, int (*initialized)(void), unsigned long before,
                                          const struct image_view *image)
{
    pid_t child = fork();
    if (child == 0) {
        struct syscall_filter_instruction instructions[] = {
            {0x20, 0, 0, 0},
            {0x15, 0, 1, (unsigned int)number},
            {0x06, 0, 0, 0x00050000 | EPERM},
            {0x06, 0, 0, 0x7fff0000},
        };
        struct syscall_filter_program program = {4, instructions};
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, 2, &program, 0, 0)) _exit(2);
        errno = 0;
        long injected = number == SYS_mprotect ? syscall(SYS_mprotect, 0, 4096, 1)
            : syscall(SYS_mmap, 0, 4096, 3, 0x22, -1, 0);
        if (injected != -1 || errno != EPERM) _exit(3);
        void *rejected = dlopen("/usr/lib/rejected-source.so", RTLD_NOW);
        const char *error = dlerror();
        unsigned long after = 0;
        dl_iterate_phdr(count_dso, &after);
        _exit(!rejected && error && (number != SYS_mprotect || strstr(error, "RELRO protection failed"))
              && after == before && initialized() == 7 && access("/rejected-marker", F_OK) != 0
              && check_relro(image->base, image->headers, image->count) ? 0 : 1);
    }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int check_loaded_dso(void)
{
    void *handle = dlopen("/usr/lib/hardened-relro-fixture.so", RTLD_NOW);
    if (!handle) return 0;
    int (*initialized)(void) = (int (*)(void))dlsym(handle, "hardened_fixture_initialized");
    struct image_view image = {0};
    int found = dl_iterate_phdr(find_dso, &image);
    int valid = initialized && initialized() == 7 && found == 1
        && check_relro(image.base, image.headers, image.count);
    void *relative = dlopen("plugins/relative-only.so", RTLD_NOW);
    if (relative) { dlclose(relative); valid = 0; }
    void *absolute = dlopen("/plugins/relative-only.so", RTLD_NOW);
    if (!absolute || dlclose(absolute) != 0) valid = 0;
    pid_t child = fork();
    if (child == 0) {
        void *control = dlopen("/usr/lib/rejected-source.so", RTLD_NOW);
        _exit(control && access("/rejected-marker", F_OK) == 0 ? 0 : 1);
    }
    int child_status = 0;
    if (child < 0 || waitpid(child, &child_status, 0) != child
        || !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0
        || unlink("/rejected-marker") != 0) valid = 0;
    unsigned long before = 0;
    dl_iterate_phdr(count_dso, &before);
    if (valid && (!failed_syscall_preserves_graph(SYS_mprotect, initialized, before, &image)
                  || !failed_syscall_preserves_graph(SYS_mmap, initialized, before, &image))) valid = 0;
    const char *rejected[] = {"/usr/lib/rejected-stack.so", "/usr/lib/rejected-wx.so", "/usr/lib/rejected-relro.so"};
    for (unsigned long i = 0; valid && i < sizeof rejected / sizeof rejected[0]; i++) {
        if (access(rejected[i], F_OK) != 0) { valid = 0; break; }
        void *bad = dlopen(rejected[i], RTLD_LAZY);
        if (bad) {
            dlclose(bad);
            valid = 0;
            break;
        }
        unsigned long after = 0;
        dl_iterate_phdr(count_dso, &after);
        if (before != after || initialized() != 7 || access("/rejected-marker", F_OK) == 0) valid = 0;
    }
    return dlclose(handle) == 0 && valid;
}
#endif

__attribute__((constructor)) static void observe_relro(void)
{
    const Elf64_Phdr *headers = (const Elf64_Phdr *)getauxval(AT_PHDR);
    unsigned long count = getauxval(AT_PHNUM);
    uintptr_t base = 0;
    int found = 0;
    for (unsigned long i = 0; i < count; i++) {
        if (headers[i].p_type == PT_PHDR) {
            base = (uintptr_t)headers - headers[i].p_vaddr;
            found = 1;
        }
    }
    if (!found) return;
    if (!check_relro(base, headers, count)) return;
    for (unsigned long i = 0; i < count; i++) {
        if (headers[i].p_type != PT_INTERP) continue;
        uintptr_t interpreter = getauxval(AT_BASE);
        if (!interpreter) return;
        const Elf64_Ehdr *elf = (const Elf64_Ehdr *)interpreter;
        const Elf64_Phdr *programs = (const Elf64_Phdr *)(interpreter + elf->e_phoff);
        if (!check_relro(interpreter, programs, elf->e_phnum)) return;
    }
#ifdef CRABC_DSO_PROBE
    if (!check_loaded_dso()) return;
#endif
    protected_before_main = 1;
}

int main(void)
{
    return protected_before_main ? 0 : 1;
}
