/* Static crabc-libc x86-64 uname/sysinfo fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6,
 * then through a freestanding executable linked solely with the selected
 * crabc `libc.a`. It selects only the `uname` and `sysinfo` C boundaries.
 * Linux writes all 390 bytes of `struct utsname` and the 112-byte kernel
 * prefix of the 368-byte public `struct sysinfo`; the latter record's final
 * 252 compatibility bytes are caller-resident and must retain their sentinel.
 * This is not gethostname, process identity, system-file parsing, CRT,
 * pthread/TLS lifecycle, loader, sysroot, or public x86 support.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

enum {
    SYSINFO_KERNEL_BYTES = 112,
    SYSINFO_RESERVED_KERNEL_BYTES = 4,
    SYSINFO_TAIL_SENTINEL = 0xa5,
};

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SI_LOAD_SHIFT == 16, "x86 sysinfo load scale");
_Static_assert(sizeof(struct utsname) == 390 && _Alignof(struct utsname) == 1,
    "x86 utsname layout");
_Static_assert(offsetof(struct utsname, sysname) == 0 &&
    offsetof(struct utsname, nodename) == 65 &&
    offsetof(struct utsname, release) == 130 &&
    offsetof(struct utsname, version) == 195 &&
    offsetof(struct utsname, machine) == 260 &&
    offsetof(struct utsname, domainname) == 325,
    "x86 utsname field offsets");
_Static_assert(sizeof(((struct utsname *)0)->sysname) == 65 &&
    sizeof(((struct utsname *)0)->nodename) == 65 &&
    sizeof(((struct utsname *)0)->release) == 65 &&
    sizeof(((struct utsname *)0)->version) == 65 &&
    sizeof(((struct utsname *)0)->machine) == 65 &&
    sizeof(((struct utsname *)0)->domainname) == 65,
    "x86 utsname field widths");
_Static_assert(sizeof(struct sysinfo) == 368 && _Alignof(struct sysinfo) == 8,
    "x86 public sysinfo layout");
_Static_assert(offsetof(struct sysinfo, uptime) == 0 &&
    offsetof(struct sysinfo, loads) == 8 &&
    offsetof(struct sysinfo, totalram) == 32 &&
    offsetof(struct sysinfo, freeram) == 40 &&
    offsetof(struct sysinfo, sharedram) == 48 &&
    offsetof(struct sysinfo, bufferram) == 56 &&
    offsetof(struct sysinfo, totalswap) == 64 &&
    offsetof(struct sysinfo, freeswap) == 72 &&
    offsetof(struct sysinfo, procs) == 80 &&
    offsetof(struct sysinfo, pad) == 82 &&
    offsetof(struct sysinfo, totalhigh) == 88 &&
    offsetof(struct sysinfo, freehigh) == 96 &&
    offsetof(struct sysinfo, mem_unit) == 104 &&
    offsetof(struct sysinfo, __reserved) == 108,
    "x86 public sysinfo field offsets");
_Static_assert(sizeof(((struct sysinfo *)0)->loads) == 24 &&
    sizeof(((struct sysinfo *)0)->procs) == 2 &&
    sizeof(((struct sysinfo *)0)->pad) == 2 &&
    sizeof(((struct sysinfo *)0)->mem_unit) == 4 &&
    sizeof(((struct sysinfo *)0)->__reserved) == 256,
    "x86 public sysinfo field widths");
_Static_assert(SYS_uname == 63 && SYS_sysinfo == 99,
    "x86 selected system-observation syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&uname),
    int (*)(struct utsname *)), "uname declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sysinfo),
    int (*)(struct sysinfo *)), "sysinfo declaration");

static void fill_bytes(void *value, size_t length, unsigned char byte)
{
    unsigned char *bytes = value;
    size_t index;

    for (index = 0; index < length; index++)
        bytes[index] = byte;
}

static int has_linux_sysname(const struct utsname *name)
{
    return name->sysname[0] == 'L' && name->sysname[1] == 'i' &&
        name->sysname[2] == 'n' && name->sysname[3] == 'u' &&
        name->sysname[4] == 'x' && name->sysname[5] == '\0';
}

static int check_null_pointer_errors(void)
{
    errno = 0;
    if (uname(NULL) != -1 || errno != EFAULT)
        return 1;
    errno = 0;
    if (sysinfo(NULL) != -1 || errno != EFAULT)
        return 2;
    return 0;
}

static int check_uname_record(void)
{
    struct utsname name;

    fill_bytes(&name, sizeof(name), SYSINFO_TAIL_SENTINEL);
    if (uname(&name) != 0)
        return 1;
    if (!has_linux_sysname(&name))
        return 2;
    if (name.machine[0] == '\0' || name.sysname[64] != '\0' ||
        name.nodename[64] != '\0' || name.release[64] != '\0' ||
        name.version[64] != '\0' || name.machine[64] != '\0' ||
        name.domainname[64] != '\0')
        return 3;
    return 0;
}

static int check_sysinfo_record_and_tail(void)
{
    struct sysinfo info;
    size_t index;

    fill_bytes(&info, sizeof(info), SYSINFO_TAIL_SENTINEL);
    if (sysinfo(&info) != 0)
        return 1;
    if (info.procs == 0)
        return 2;

    /* Linux's ABI record is 112 bytes. Its final four bytes occupy the
     * beginning of musl's public compatibility field and are initialized by
     * the kernel; only offsets 112 through 367 are caller-resident. */
    for (index = 0; index < SYSINFO_RESERVED_KERNEL_BYTES; index++)
        if ((unsigned char)info.__reserved[index] != 0)
            return 3;
    for (index = SYSINFO_RESERVED_KERNEL_BYTES;
         index < sizeof(info.__reserved); index++)
        if ((unsigned char)info.__reserved[index] != SYSINFO_TAIL_SENTINEL)
            return 4;
    return 0;
}

int crabc_x86_64_system_observation_probe(void)
{
    int status;

    status = check_null_pointer_errors();
    if (status != 0)
        return status;
    status = check_uname_record();
    if (status != 0)
        return 10 + status;
    status = check_sysinfo_record_and_tail();
    if (status != 0)
        return 20 + status;
    return 0;
}

#ifndef CRABC_SYSTEM_OBSERVATION_FREESTANDING
int main(void)
{
    return crabc_x86_64_system_observation_probe();
}
#endif
