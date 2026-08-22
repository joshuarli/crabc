#define _GNU_SOURCE

#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>

struct loader_state {
    uintptr_t base;
    int found;
};

static int find_interpreter(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct loader_state *state = opaque;

    if (size < sizeof(*info))
        return 90;
    if ((uintptr_t)info->dlpi_addr != state->base)
        return 0;
    if (info->dlpi_phdr == NULL || info->dlpi_phnum == 0)
        return 91;

    state->found = 1;
    return 1;
}

int main(void)
{
    /* A dynamically interpreted ELF program receives the actual interpreter
       load address in AT_BASE.  Finding that same object through the loader's
       post-startup image list proves the interpreter reached initialized Rust
       state after its AArch64 relative-relocation startup path. */
    unsigned long base = getauxval(AT_BASE);
    if (base == 0)
        return 1;

    struct loader_state state = { (uintptr_t)base, 0 };
    if (dl_iterate_phdr(find_interpreter, &state) != 1)
        return 2;
    if (!state.found)
        return 3;

    puts("ldso self relocation ok");
    return 0;
}
