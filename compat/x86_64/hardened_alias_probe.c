#include <elf.h>
#include <stdint.h>
#include <sys/auxv.h>

static volatile unsigned char writable_value = 0x5a;

int main(void)
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
    if (!found) return 1;
    uintptr_t value = (uintptr_t)&writable_value - base;
    for (unsigned long i = 0; i < count; i++) {
        const Elf64_Phdr *write = &headers[i];
        if (write->p_type != PT_LOAD || !(write->p_flags & PF_W)
            || value < write->p_vaddr || value >= write->p_vaddr + write->p_filesz) continue;
        uintptr_t offset = write->p_offset + value - write->p_vaddr;
        for (unsigned long j = 0; j < count; j++) {
            const Elf64_Phdr *execute = &headers[j];
            uintptr_t file_start = execute->p_offset & ~(uintptr_t)4095;
            uintptr_t file_end = (execute->p_offset + execute->p_filesz + 4095) & ~(uintptr_t)4095;
            if (execute->p_type != PT_LOAD || !(execute->p_flags & PF_X)
                || offset < file_start || offset >= file_end) continue;
            uintptr_t virtual_start = execute->p_vaddr & ~(uintptr_t)4095;
            const volatile unsigned char *alias = (const volatile unsigned char *)(base + virtual_start + offset - file_start);
            if (*alias != 0x5a) return 2;
            writable_value = 0x23;
            return *alias == 0x5a ? 0 : 3;
        }
    }
    return 4;
}
