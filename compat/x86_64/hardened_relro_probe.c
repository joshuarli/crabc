#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef CRABC_DSO_PROBE
#include <dlfcn.h>
#include <link.h>
#include <string.h>
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

static int check_loaded_dso(void)
{
    void *handle = dlopen("/usr/lib/hardened-relro-fixture.so", RTLD_NOW);
    if (!handle) return 0;
    int (*initialized)(void) = (int (*)(void))dlsym(handle, "hardened_fixture_initialized");
    struct image_view image = {0};
    int found = dl_iterate_phdr(find_dso, &image);
    int valid = initialized && initialized() == 7 && found == 1
        && check_relro(image.base, image.headers, image.count);
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
