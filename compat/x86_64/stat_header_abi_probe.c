/* Source-only Linux/x86-64 <sys/stat.h> declaration and layout probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/stat.h>

_Static_assert(sizeof(dev_t) == 8 && sizeof(ino_t) == 8,
    "x86 stat device/inode widths");
_Static_assert(sizeof(nlink_t) == 8 && sizeof(mode_t) == 4,
    "x86 stat link-count/mode widths");
_Static_assert(sizeof(struct stat) == 144 && _Alignof(struct stat) == 8,
    "x86 struct stat size/alignment");
_Static_assert(offsetof(struct stat, st_dev) == 0,
    "x86 struct stat st_dev");
_Static_assert(offsetof(struct stat, st_ino) == 8,
    "x86 struct stat st_ino");
_Static_assert(offsetof(struct stat, st_nlink) == 16,
    "x86 struct stat st_nlink");
_Static_assert(offsetof(struct stat, st_mode) == 24,
    "x86 struct stat st_mode");
_Static_assert(offsetof(struct stat, st_uid) == 28,
    "x86 struct stat st_uid");
_Static_assert(offsetof(struct stat, st_gid) == 32,
    "x86 struct stat st_gid");
_Static_assert(offsetof(struct stat, st_rdev) == 40,
    "x86 struct stat st_rdev");
_Static_assert(offsetof(struct stat, st_size) == 48,
    "x86 struct stat st_size");
_Static_assert(offsetof(struct stat, st_blksize) == 56,
    "x86 struct stat st_blksize");
_Static_assert(offsetof(struct stat, st_blocks) == 64,
    "x86 struct stat st_blocks");
_Static_assert(offsetof(struct stat, st_atim) == 72 &&
    offsetof(struct stat, st_mtim) == 88 &&
    offsetof(struct stat, st_ctim) == 104,
    "x86 struct stat timestamps");

_Static_assert(S_IFMT == 0170000 && S_IFDIR == 0040000 &&
    S_IFREG == 0100000 && S_IFLNK == 0120000 && S_IFSOCK == 0140000,
    "stat file-type macros");
_Static_assert(S_IRWXU == 0700 && S_IRWXG == 0070 && S_IRWXO == 0007 &&
    S_ISUID == 04000 && S_ISGID == 02000 && S_ISVTX == 01000,
    "stat permission macros");
_Static_assert(UTIME_NOW == 0x3fffffff && UTIME_OMIT == 0x3ffffffe,
    "stat timestamp macros");

_Static_assert(__builtin_types_compatible_p(__typeof__(&stat),
    int (*)(const char *, struct stat *)), "stat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fstat),
    int (*)(int, struct stat *)), "fstat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fchmod),
    int (*)(int, mode_t)), "fchmod declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mkdir),
    int (*)(const char *, mode_t)), "mkdir declaration");

int crabc_x86_64_stat_header_abi_probe(void)
{
    struct stat value = {0};
    return S_ISREG(value.st_mode) ? 0 : (int)sizeof(value);
}
