/* C++ source-only Linux/x86-64 system-header ABI probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

static_assert(SI_LOAD_SHIFT == 16, "musl SI_LOAD_SHIFT");
static_assert(sizeof(struct utsname) == 390, "x86 utsname size");
static_assert(alignof(struct utsname) == 1, "x86 utsname alignment");
static_assert(offsetof(struct utsname, machine) == 260, "x86 utsname machine offset");
static_assert(sizeof(struct sysinfo) == 368, "x86 sysinfo size");
static_assert(alignof(struct sysinfo) == 8, "x86 sysinfo alignment");
static_assert(offsetof(struct sysinfo, uptime) == 0, "sysinfo uptime offset");
static_assert(offsetof(struct sysinfo, loads) == 8, "sysinfo loads offset");
static_assert(offsetof(struct sysinfo, procs) == 80, "sysinfo procs offset");
static_assert(offsetof(struct sysinfo, totalhigh) == 88, "sysinfo high-memory offset");
static_assert(offsetof(struct sysinfo, mem_unit) == 104, "sysinfo unit offset");
static_assert(offsetof(struct sysinfo, __reserved) == 108, "sysinfo compatibility tail offset");

static int (*uname_signature)(struct utsname *) = uname;
static int (*sysinfo_signature)(struct sysinfo *) = sysinfo;

int crabc_x86_64_system_header_abi_probe()
{
    return uname_signature != nullptr && sysinfo_signature != nullptr;
}
