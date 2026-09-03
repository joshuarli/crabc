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

#if defined(_GNU_SOURCE)
typedef int (*statx_function)(int, const char *__restrict, int, unsigned,
    struct statx *__restrict);

_Static_assert(STATX_TYPE == 1U && STATX_MODE == 2U &&
    STATX_NLINK == 4U && STATX_UID == 8U && STATX_GID == 0x10U &&
    STATX_ATIME == 0x20U && STATX_MTIME == 0x40U && STATX_CTIME == 0x80U &&
    STATX_INO == 0x100U && STATX_SIZE == 0x200U && STATX_BLOCKS == 0x400U &&
    STATX_BASIC_STATS == 0x7ffU && STATX_BTIME == 0x800U &&
    STATX_ALL == 0xfffU && STATX_MNT_ID == 0x1000U &&
    STATX_DIOALIGN == 0x2000U && STATX_MNT_ID_UNIQUE == 0x4000U &&
    STATX_SUBVOL == 0x8000U && STATX_WRITE_ATOMIC == 0x10000U,
    "statx request-mask macros");
_Static_assert(STATX_ATTR_COMPRESSED == 0x4 &&
    STATX_ATTR_IMMUTABLE == 0x10 && STATX_ATTR_APPEND == 0x20 &&
    STATX_ATTR_NODUMP == 0x40 && STATX_ATTR_ENCRYPTED == 0x800 &&
    STATX_ATTR_AUTOMOUNT == 0x1000 && STATX_ATTR_MOUNT_ROOT == 0x2000 &&
    STATX_ATTR_VERITY == 0x100000 && STATX_ATTR_DAX == 0x200000 &&
    STATX_ATTR_WRITE_ATOMIC == 0x400000,
    "statx attribute macros");
#ifdef STATX__RESERVED
#error "pinned musl does not publish STATX__RESERVED"
#endif
_Static_assert(sizeof(struct statx_timestamp) == 16 &&
    _Alignof(struct statx_timestamp) == 8 &&
    offsetof(struct statx_timestamp, tv_sec) == 0 &&
    offsetof(struct statx_timestamp, tv_nsec) == 8 &&
    offsetof(struct statx_timestamp, __pad) == 12,
    "statx timestamp layout");
_Static_assert(sizeof(struct statx) == 256 && _Alignof(struct statx) == 8,
    "statx layout size/alignment");
_Static_assert(offsetof(struct statx, stx_mask) == 0 &&
    offsetof(struct statx, stx_blksize) == 4 &&
    offsetof(struct statx, stx_attributes) == 8 &&
    offsetof(struct statx, stx_nlink) == 16 &&
    offsetof(struct statx, stx_uid) == 20 &&
    offsetof(struct statx, stx_gid) == 24 &&
    offsetof(struct statx, stx_mode) == 28 &&
    offsetof(struct statx, __pad0) == 30 &&
    offsetof(struct statx, stx_ino) == 32 &&
    offsetof(struct statx, stx_size) == 40 &&
    offsetof(struct statx, stx_blocks) == 48 &&
    offsetof(struct statx, stx_attributes_mask) == 56,
    "statx leading layout");
_Static_assert(offsetof(struct statx, stx_atime) == 64 &&
    offsetof(struct statx, stx_btime) == 80 &&
    offsetof(struct statx, stx_ctime) == 96 &&
    offsetof(struct statx, stx_mtime) == 112 &&
    offsetof(struct statx, stx_rdev_major) == 128 &&
    offsetof(struct statx, stx_rdev_minor) == 132 &&
    offsetof(struct statx, stx_dev_major) == 136 &&
    offsetof(struct statx, stx_dev_minor) == 140,
    "statx timestamp and device layout");
_Static_assert(offsetof(struct statx, stx_mnt_id) == 144 &&
    offsetof(struct statx, stx_dio_mem_align) == 152 &&
    offsetof(struct statx, stx_dio_offset_align) == 156 &&
    offsetof(struct statx, stx_subvol) == 160 &&
    offsetof(struct statx, stx_atomic_write_unit_min) == 168 &&
    offsetof(struct statx, stx_atomic_write_unit_max) == 172 &&
    offsetof(struct statx, stx_atomic_write_segments_max) == 176 &&
    offsetof(struct statx, __pad1) == 180 &&
    offsetof(struct statx, __pad2) == 184,
    "statx trailing layout");
_Static_assert(__builtin_types_compatible_p(__typeof__(&statx), statx_function),
    "statx declaration");
#else
#ifdef STATX_TYPE
#error "statx request-mask macros require _GNU_SOURCE in C"
#endif
#ifdef STATX_ATTR_COMPRESSED
#error "statx attribute macros require _GNU_SOURCE in C"
#endif
#endif

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
