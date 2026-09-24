/* Musl differential for malformed dlopen inputs that pinned musl 1.2.6
 * ldso/dynlink.c::map_library rejects (see
 * general_dynamic_dlfcn_contract_malformed.py; `needs` depends on a
 * relocatable libmf_dep.so). Each named case must fail
 * with musl's text, publish no image and leave dlpi_adds unchanged; NOLOAD
 * then reports it not loaded, and the valid source object still loads.
 * Output is the comparison surface.
 *
 * Usage: consumer CASE... */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>

#include "general_dynamic_dlfcn_contract.h"

struct images { unsigned count; unsigned long long adds; };

static int count_images(struct dl_phdr_info *info, size_t size, void *data)
{
    struct images *images = data;
    (void)size;
    images->adds = info->dlpi_adds;
    if (info->dlpi_name && strstr(info->dlpi_name, "libmf_")) images->count++;
    return 0;
}

int main(int argc, char **argv)
{
    struct images before = {0, 0}, after = {0, 0};
    dl_iterate_phdr(count_images, &before);
    for (int index = 1; index < argc; ++index) {
        char name[128], label[160];
        snprintf(name, sizeof name, "libmf_%s.so", argv[index]);
        printf("%s: %s\n", argv[index], result(dlopen(name, RTLD_NOW | RTLD_GLOBAL)));
        show_error(argv[index]);
        snprintf(label, sizeof label, "%s NOLOAD", argv[index]);
        printf("%s: %s\n", label, result(dlopen(name, RTLD_NOW | RTLD_NOLOAD)));
        show_error(label);
    }
    dl_iterate_phdr(count_images, &after);
    printf("after malformed: images=%u adds delta=%llu\n", after.count, after.adds - before.adds);
    void *valid = dlopen("libmf_valid.so", RTLD_NOW);
    int *value = valid ? dlsym(valid, "dc_plain_value") : 0;
    printf("valid: %s value=%d\n", result(valid), value ? *value : -1);
    dl_iterate_phdr(count_images, &after);
    printf("after valid: images=%u adds delta=%llu\n", after.count, after.adds - before.adds);
    puts("malformed contract: complete");
    return 0;
}
