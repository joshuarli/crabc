#include <dlfcn.h>
#include <link.h>
#include <stddef.h>

static_assert(sizeof(Dl_info) == 32, "Dl_info x86 LP64 ABI");
static_assert(offsetof(Dl_info, dli_saddr) == 24, "Dl_info x86 tail");
static_assert(sizeof(struct link_map) == 40, "link_map x86 LP64 ABI");
static_assert(sizeof(struct dl_phdr_info) == 64, "dl_phdr_info x86 LP64 ABI");

extern "C" int crabc_x86_64_public_dlfcn_cpp_probe(
    void *handle, const void *address, struct dl_phdr_info *information,
    int (*callback)(struct dl_phdr_info *, size_t, void *)) {
    Dl_info result;
    struct link_map *map = nullptr;
    void *opened = dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
    void *symbol = dlsym(handle, "mid_value");
    int status = dladdr(address, &result) + dlinfo(handle, RTLD_DI_LINKMAP, &map);
    status += dl_iterate_phdr(callback, information);
    status += dlclose(opened);
    return status + (dlerror() != nullptr) + (symbol != nullptr) + (map != nullptr);
}
