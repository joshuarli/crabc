/* Initial-process ABI fixture, compiled as an application through crabc-cc. */
#include <elf.h>
#include <stdint.h>
#include <string.h>
#include <sys/auxv.h>
#include <stdlib.h>
#include <unistd.h>

extern char **environ;

static int matching(const char *left, const char *right)
{
    return left != 0 && right != 0 && strcmp(left, right) == 0;
}

int main(int argc, char **argv, char **envp)
{
    uintptr_t *auxv;
    uintptr_t stack_pointer;
    unsigned long pagesz;
    unsigned long phdr;
    unsigned long phent;
    unsigned long phnum;
    unsigned long entry;
    unsigned long execfn;
    unsigned long random;
    int envc = 0;
    int auxc = 0;
    int saw_null = 0;

    __asm__ volatile("mov %0, sp" : "=r"(stack_pointer));
    if (stack_pointer % 16 != 0)
        return 10;
    if (argc != 3 || argv == 0 || envp == 0 || argv[argc] != 0)
        return 11;
    if (!matching(argv[1], "first") || !matching(argv[2], "second"))
        return 12;
    if (environ != envp)
        return 13;
    while (envp[envc] != 0) {
        if (++envc > (1 << 20))
            return 14;
    }
    auxv = (uintptr_t *)(envp + envc + 1);
    while (auxc < 4096) {
        if (auxv[auxc * 2] == AT_NULL) {
            saw_null = 1;
            break;
        }
        ++auxc;
    }
    if (!saw_null)
        return 15;

    pagesz = getauxval(AT_PAGESZ);
    phdr = getauxval(AT_PHDR);
    phent = getauxval(AT_PHENT);
    phnum = getauxval(AT_PHNUM);
    entry = getauxval(AT_ENTRY);
    execfn = getauxval(AT_EXECFN);
    random = getauxval(AT_RANDOM);
    if (pagesz == 0 || phdr == 0 || phent != sizeof(Elf64_Phdr) || phnum == 0 || entry == 0)
        return 16;
    if (execfn == 0 || !matching((const char *)execfn, argv[0]) || random == 0)
        return 17;
    if (getenv("CRABC_STARTUP_PRINT_ADDRESS") != 0) {
        uintptr_t address = (uintptr_t)&main;
        if (write(1, &address, sizeof(address)) != sizeof(address))
            return 18;
    }
    return 73;
}
