#include <elf.h>
#include <stdio.h>
#include <sys/auxv.h>

int main(void)
{
    unsigned long required[] = {
        AT_PHDR,
        AT_PHNUM,
        AT_ENTRY,
        AT_BASE,
        AT_RANDOM,
        AT_SYSINFO_EHDR,
    };
    for (unsigned long i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        if (getauxval(required[i]) == 0)
            return 10 + (int)i;
    }
    puts("auxv=ok");
    return 0;
}
