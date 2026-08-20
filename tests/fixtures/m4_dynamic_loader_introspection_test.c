#define _GNU_SOURCE

#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>

struct callback_state {
    int count;
    int nonempty_name;
    int valid_metadata;
    int stop_value;
};

static int inspect_object(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct callback_state *state = opaque;
    if (size < sizeof(*info) || info->dlpi_phdr == NULL || info->dlpi_phnum == 0)
        return 91;
    state->count++;
    if (info->dlpi_name != NULL && info->dlpi_name[0] != '\0')
        state->nonempty_name = 1;
    if (info->dlpi_addr != 0 && info->dlpi_phdr != NULL)
        state->valid_metadata = 1;
    if (state->stop_value != 0)
        return state->stop_value;
    return 0;
}

int main(void)
{
    Dl_info address_info;
    memset(&address_info, 0, sizeof(address_info));
    if (dladdr((const void *)&main, &address_info) != 1)
        return 1;
    if (address_info.dli_fname == NULL || address_info.dli_fbase == NULL)
        return 2;
    if (dladdr((const void *)1, &address_info) != 0)
        return 3;

    void *handle = dlopen("libc.so", RTLD_NOW);
    if (handle == NULL)
        return 4;
    struct link_map *map = NULL;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || map == NULL)
        return 5;
    if (map->l_name == NULL || map->l_ld == NULL || map->l_addr == 0)
        return 6;

    struct callback_state stopped = {0, 0, 0, 17};
    if (dl_iterate_phdr(inspect_object, &stopped) != 17 || stopped.count != 1)
        return 7;

    struct callback_state all = {0, 0, 0, 0};
    if (dl_iterate_phdr(inspect_object, &all) != 0)
        return 8;
    if (all.count < 2 || !all.nonempty_name || !all.valid_metadata)
        return 9;

    puts("ok");
    return 0;
}
