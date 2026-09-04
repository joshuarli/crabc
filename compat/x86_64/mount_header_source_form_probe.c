/* Direct pinned-musl x86 <sys/mount.h> source-form and ABI witness. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/mount.h>

#ifndef _SYS_MOUNT_H
#error "<sys/mount.h> must retain musl's public guard"
#endif
#ifdef _LINUX_MOUNT_H
#error "<sys/mount.h> must not acquire Linux UAPI mount declarations"
#endif

_Static_assert(BLKROSET == _IO(0x12, 93) && BLKGETSIZE64 == _IOR(0x12,114,size_t),
    "block ioctl source vocabulary");
_Static_assert(MS_RDONLY == 1 && MS_BIND == 4096 && MS_REC == 16384 &&
    MS_LAZYTIME == (1<<25) && MS_NOUSER == (1U<<31),
    "classic mount flag vocabulary");
_Static_assert(MS_RMT_MASK ==
    (MS_RDONLY|MS_SYNCHRONOUS|MS_MANDLOCK|MS_I_VERSION|MS_LAZYTIME),
    "mount remount mask source composition");
_Static_assert(__builtin_types_compatible_p(__typeof__(MS_MGC_VAL), unsigned int) &&
    __builtin_types_compatible_p(__typeof__(MS_MGC_MSK), unsigned int),
    "mount magic constants retain musl's unsuffixed integer type");
_Static_assert(MS_MGC_VAL == 0xc0ed0000 && MS_MGC_MSK == 0xffff0000,
    "mount magic constants");
_Static_assert(MNT_FORCE == 1 && MNT_DETACH == 2 && MNT_EXPIRE == 4 &&
    UMOUNT_NOFOLLOW == 8, "unmount flag vocabulary");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mount),
    int (*)(const char *, const char *, const char *, unsigned long, const void *)),
    "mount declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&umount), int (*)(const char *)),
    "umount declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&umount2),
    int (*)(const char *, int)), "umount2 declaration");

int crabc_x86_mount_header_source_form_probe(void)
{
    return MS_RDONLY == 1 ? 0 : 1;
}
