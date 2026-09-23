#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef PHDR_PROVIDER
/* The mutator copies the complete PHDR table over this unused, file-backed
 * part of a readable PT_LOAD. Keep the marker beyond the first file page. */
static const unsigned char phdr_reserve[8192] __attribute__((used, aligned(64))) = {
    [4096] = 'L', [4097] = 'A', [4098] = 'T', [4099] = 'E',
    [4100] = 'P', [4101] = 'H', [4102] = 'D', [4103] = 'R',
};

int late_phdr_value(void) { return 37; }
#else
struct phdr_state { int found; };

static int inspect(struct dl_phdr_info *info, size_t size, void *argument)
{
    struct phdr_state *state = argument;
    if (!strstr(info->dlpi_name, "libphdr-late.so")) return 0;
    if (size < sizeof *info || info->dlpi_phnum == 0 || !info->dlpi_phdr) return -1;
    uintptr_t table = (uintptr_t)info->dlpi_phdr;
    size_t table_size = info->dlpi_phnum * sizeof *info->dlpi_phdr;
    int covered = 0;
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *load = &info->dlpi_phdr[i];
        if (load->p_type != PT_LOAD || !(load->p_flags & PF_R)) continue;
        uintptr_t start = info->dlpi_addr + load->p_vaddr;
        if (table < start || table - start > load->p_filesz
            || table_size > load->p_filesz - (table - start)) continue;
        if (load->p_offset + (table - start) > 4096) covered = 1;
    }
    if (!covered) return -1;
    ++state->found;
    return 0;
}

int main(void)
{
    void *handle = dlopen("libphdr-late.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 1;
    int (*value)(void) = dlsym(handle, "late_phdr_value");
    if (!value || value() != 37) return 2;
    struct phdr_state state = {0};
    if (dl_iterate_phdr(inspect, &state) || state.found != 1) return 3;
    if (dlclose(handle)) return 4;
    puts("late PHDR: mapped table and symbol");
    return 0;
}
#endif
