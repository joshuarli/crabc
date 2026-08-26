/* Source-only Linux/x86-64 <sys/utsname.h> and <sys/sysinfo.h> ABI probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

_Static_assert(SI_LOAD_SHIFT == 16, "musl SI_LOAD_SHIFT");
_Static_assert(sizeof(struct utsname) == 390, "x86 utsname size");
_Static_assert(_Alignof(struct utsname) == 1, "x86 utsname alignment");
_Static_assert(offsetof(struct utsname, machine) == 260, "x86 utsname machine offset");
_Static_assert(sizeof(struct sysinfo) == 368, "x86 sysinfo size");
_Static_assert(_Alignof(struct sysinfo) == 8, "x86 sysinfo alignment");
_Static_assert(offsetof(struct sysinfo, uptime) == 0, "sysinfo uptime offset");
_Static_assert(offsetof(struct sysinfo, loads) == 8, "sysinfo loads offset");
_Static_assert(offsetof(struct sysinfo, procs) == 80, "sysinfo procs offset");
_Static_assert(offsetof(struct sysinfo, totalhigh) == 88, "sysinfo high-memory offset");
_Static_assert(offsetof(struct sysinfo, mem_unit) == 104, "sysinfo unit offset");
_Static_assert(offsetof(struct sysinfo, __reserved) == 108, "sysinfo compatibility tail offset");

static int (*uname_signature)(struct utsname *) = uname;
static int (*sysinfo_signature)(struct sysinfo *) = sysinfo;

int crabc_x86_64_system_header_abi_probe(void)
{
    return uname_signature != 0 && sysinfo_signature != 0 && SI_LOAD_SHIFT;
}
