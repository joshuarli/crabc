/*
 * Direct pinned-musl x86 <link.h> source-form assertions.  This deliberately
 * includes no convenience header: <link.h> itself must request only the
 * typedefs it needs and must publish Elf_Symndx through <bits/link.h>.
 */
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

_Static_assert(sizeof(Elf_Symndx) == sizeof(uint32_t),
    "bits/link.h must publish Elf_Symndx");
_Static_assert(__builtin_types_compatible_p(Elf_Symndx, uint32_t),
    "Elf_Symndx spelling");
_Static_assert(sizeof(ElfW(Addr)) == sizeof(Elf64_Addr),
    "x86 ElfW must select ELF64");
_Static_assert(sizeof(struct dl_phdr_info) == 64 &&
    __builtin_offsetof(struct dl_phdr_info, dlpi_tls_data) == 56,
    "dl_phdr_info x86 layout");
_Static_assert(sizeof(struct link_map) == 40 &&
    __builtin_offsetof(struct link_map, l_prev) == 32,
    "link_map x86 layout");
_Static_assert(sizeof(struct r_debug) == 40 &&
    __builtin_offsetof(struct r_debug, r_ldbase) == 32,
    "r_debug x86 layout");
_Static_assert(__builtin_types_compatible_p(__typeof__(&dl_iterate_phdr),
    int (*)(int (*)(struct dl_phdr_info *, size_t, void *), void *)),
    "dl_iterate_phdr declaration");

int crabc_x86_link_header_source_form_probe(void)
{
    return 0;
}
