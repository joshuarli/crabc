#include <dlfcn.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

extern void *__tls_get_addr(const size_t *);

struct tls_dso_info {
    void *address;
    size_t module;
    void *tls_data;
};

static int find_tls_dso(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct tls_dso_info *wanted = opaque;
    (void)size;
    if (info->dlpi_name && strcmp(info->dlpi_name, "libtls_get_addr.so") == 0) {
        wanted->module = info->dlpi_tls_modid;
        wanted->tls_data = info->dlpi_tls_data;
        return 1;
    }
    return 0;
}

int main(void)
{
    void *handle = dlopen("libtls_get_addr.so", RTLD_NOW);
    if (!handle)
        return 1;

    void *(*tls_addr)(void) = (void *(*)(void))dlsym(handle, "tls_addr");
    if (!tls_addr)
        return 2;

    struct tls_dso_info info = { tls_addr(), 0, NULL };
    if (dl_iterate_phdr(find_tls_dso, &info) != 1 || info.module == 0 || !info.tls_data)
        return 3;

    size_t offset = (size_t)((char *)info.address - (char *)info.tls_data);
    size_t index[2] = { info.module, offset };
    if (__tls_get_addr(index) != info.address)
        return 4;

    puts("tls get addr ok");
    return 0;
}
