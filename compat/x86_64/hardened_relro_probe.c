#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <unistd.h>

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
    protected_before_main = 1;
}

int main(void)
{
    return protected_before_main ? 0 : 1;
}
