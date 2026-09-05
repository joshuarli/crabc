#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#if defined(PROVIDER_A)
extern int elf_absent(void) __attribute__((weak));
__attribute__((visibility("hidden"))) int elf_hidden(void) { return 59; }
__attribute__((weak)) int elf_choice(void) { return 11; }
__attribute__((visibility("protected"))) int elf_protected(void) { return 31; }
int elf_a_call(void) { return elf_absent ? -1 : elf_choice() * 100 + elf_protected(); }
#elif defined(PROVIDER_B)
int elf_choice(void) { return 22; }
int elf_protected(void) { return 42; }
int elf_b_call(void) { return elf_choice() * 100 + elf_protected(); }
#else
static int call(void *handle, const char *name)
{
    int (*fn)(void) = (int (*)(void))dlsym(handle, name);
    return fn ? fn() : -1;
}
int main(void)
{
#ifdef RUNTIME_SCOPE
    void *first = dlopen(FIRST_LIBRARY, RTLD_NOW | RTLD_GLOBAL);
    void *second = dlopen(SECOND_LIBRARY, RTLD_NOW | RTLD_GLOBAL);
    if (!first || !second) return 1;
#endif
    void *a = dlopen("libelf_a.so", RTLD_NOW | RTLD_NOLOAD);
    void *b = dlopen("libelf_b.so", RTLD_NOW | RTLD_NOLOAD);
    if (!a || !b) return 2;
    if (call(RTLD_DEFAULT, "elf_choice") != EXPECT_CHOICE
        || call(RTLD_DEFAULT, "elf_protected") != EXPECT_PROTECTED) return 3;
    if (call(a, "elf_choice") != 11 || call(b, "elf_choice") != 22
        || call(a, "elf_protected") != 31 || call(b, "elf_protected") != 42) return 4;
    if (call(a, "elf_a_call") != EXPECT_CHOICE * 100 + 31
        || call(b, "elf_b_call") != EXPECT_CHOICE * 100 + EXPECT_PROTECTED) return 5;
    if (dlsym(a, "elf_hidden") || dlsym(RTLD_DEFAULT, "elf_hidden")
        || dlsym(a, "elf_absent")) return 6;
    if (dlclose(a) || dlclose(b)) return 7;
    puts("ELF scope: ordered weak/strong lookup and protected internal binding");
    return 0;
}
#endif
