// Direct pinned-musl x86 <link.h> C++ source-form and linkage assertions.
#include <link.h>

#ifdef offsetof
#error "<link.h> must not acquire the public <stddef.h> offsetof macro"
#endif

#ifndef __NEED_size_t
#error "<link.h> must retain musl's size_t request boundary"
#endif

#ifndef __NEED_uint32_t
#error "<link.h> must retain musl's uint32_t request boundary"
#endif

static_assert(__is_same(Elf_Symndx, uint32_t));
static_assert(sizeof(ElfW(Addr)) == sizeof(Elf64_Addr));
static_assert(sizeof(struct dl_phdr_info) == 64);
static_assert(__builtin_offsetof(struct dl_phdr_info, dlpi_tls_data) == 56);
static_assert(sizeof(struct link_map) == 40);
static_assert(__builtin_offsetof(struct link_map, l_prev) == 32);
static_assert(sizeof(struct r_debug) == 40);
static_assert(__builtin_offsetof(struct r_debug, r_ldbase) == 32);
static_assert(__is_same(decltype(&dl_iterate_phdr),
    int (*)(int (*)(struct dl_phdr_info *, size_t, void *), void *)));

extern "C" int crabc_x86_link_header_source_form_probe_cpp(
    int (*callback)(struct dl_phdr_info *, size_t, void *), void *opaque)
{
    return dl_iterate_phdr(callback, opaque);
}
