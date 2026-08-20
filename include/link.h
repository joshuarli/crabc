#ifndef _LINK_H
#define _LINK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/*
 * The loader exposes the native ELF64 program-header view on the 64-bit
 * targets supported by crabc.  Keep this header independent of musl's
 * internal bits/ headers so fixtures can compile against the public include
 * tree on both the host and the AArch64 development image.
 */
#include <elf.h>

#if UINTPTR_MAX > 0xffffffff
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif

struct dl_phdr_info {
    ElfW(Addr) dlpi_addr;
    const char *dlpi_name;
    const ElfW(Phdr) *dlpi_phdr;
    ElfW(Half) dlpi_phnum;
    unsigned long long int dlpi_adds;
    unsigned long long int dlpi_subs;
    size_t dlpi_tls_modid;
    void *dlpi_tls_data;
};

struct link_map {
    ElfW(Addr) l_addr;
    char *l_name;
    ElfW(Dyn) *l_ld;
    struct link_map *l_next;
    struct link_map *l_prev;
};

struct r_debug {
    int r_version;
    struct link_map *r_map;
    ElfW(Addr) r_brk;
    enum { RT_CONSISTENT, RT_ADD, RT_DELETE } r_state;
    ElfW(Addr) r_ldbase;
};

int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *);

#ifdef __cplusplus
}
#endif

#endif
