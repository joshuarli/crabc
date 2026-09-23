#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#ifdef UNIQUE_PROVIDER
/* GNU unique is an ordinary eligible binding in musl's OK_BINDS set. The
 * provider's own GOT reference also tests relocation of that binding. */
__asm__(".pushsection .data\n"
        ".globl elf_unique\n"
        ".type elf_unique, @gnu_unique_object\n"
        ".size elf_unique, 4\n"
        "elf_unique: .long 73\n"
        ".popsection\n");
extern int elf_unique;
int elf_unique_read(void) { return elf_unique; }
#else
int main(void)
{
    void *handle = dlopen("libelf_unique.so", RTLD_NOW | RTLD_GLOBAL);
    if (!handle) return 1;
    int *value = dlsym(handle, "elf_unique");
    int (*read_value)(void) = dlsym(handle, "elf_unique_read");
    if (!value || *value != 73 || !read_value || read_value() != 73) return 2;
    Dl_info info = {0};
    if (!dladdr(value, &info) || !info.dli_sname
        || strcmp(info.dli_sname, "elf_unique") || info.dli_saddr != value)
        return 3;
    if (dlclose(handle)) return 4;
    puts("ELF GNU unique: relocation, dlsym, dladdr");
    return 0;
}
#endif
