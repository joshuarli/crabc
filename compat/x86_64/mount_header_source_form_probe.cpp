// Direct pinned-musl x86 <sys/mount.h> source-form and C-linkage witness.

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/mount.h>

#ifdef _LINUX_MOUNT_H
#error "<sys/mount.h> must not acquire Linux UAPI mount declarations"
#endif

using mount_signature = int (*)(const char *, const char *, const char *,
    unsigned long, const void *);
using umount_signature = int (*)(const char *);
using umount2_signature = int (*)(const char *, int);

static_assert(BLKROSET == _IO(0x12, 93) && BLKGETSIZE64 == _IOR(0x12,114,size_t));
static_assert(MS_RMT_MASK ==
    (MS_RDONLY|MS_SYNCHRONOUS|MS_MANDLOCK|MS_I_VERSION|MS_LAZYTIME));
static_assert(__is_same(decltype(MS_MGC_VAL), unsigned int));
static_assert(__is_same(decltype(MS_MGC_MSK), unsigned int));
static_assert(MS_MGC_VAL == 0xc0ed0000 && MS_MGC_MSK == 0xffff0000);
static_assert(MNT_FORCE == 1 && MNT_DETACH == 2 && MNT_EXPIRE == 4 &&
    UMOUNT_NOFOLLOW == 8);
static_assert(__is_same(decltype(&mount), mount_signature));
static_assert(__is_same(decltype(&umount), umount_signature));
static_assert(__is_same(decltype(&umount2), umount2_signature));

__attribute__((used)) static mount_signature mount_reference = mount;
__attribute__((used)) static umount_signature umount_reference = umount;
__attribute__((used)) static umount2_signature umount2_reference = umount2;

extern "C" int crabc_x86_mount_header_source_form_probe_cpp()
{
    return MS_RDONLY == 1 ? 0 : 1;
}
