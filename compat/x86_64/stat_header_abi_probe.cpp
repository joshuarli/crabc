/* C++ source-only companion for the x86-64 stat header ABI probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/stat.h>

static_assert(sizeof(struct stat) == 144 && alignof(struct stat) == 8,
    "x86 struct stat C++ size/alignment");
static_assert(offsetof(struct stat, st_nlink) == 16 &&
    offsetof(struct stat, st_mode) == 24 &&
    offsetof(struct stat, st_size) == 48 &&
    offsetof(struct stat, st_blocks) == 64 &&
    offsetof(struct stat, st_ctim) == 104,
    "x86 struct stat C++ offsets");
static_assert(UTIME_NOW == 0x3fffffff && UTIME_OMIT == 0x3ffffffe,
    "x86 stat C++ timestamp macros");

using stat_function = int (*)(const char *, struct stat *);
static_assert(__is_same(decltype(&stat), stat_function),
    "x86 stat C++ declaration");

using statx_function = int (*)(int, const char *__restrict, int, unsigned,
    struct statx *__restrict);
static_assert(STATX_TYPE == 1U && STATX_MODE == 2U &&
    STATX_NLINK == 4U && STATX_UID == 8U && STATX_GID == 0x10U &&
    STATX_ATIME == 0x20U && STATX_MTIME == 0x40U && STATX_CTIME == 0x80U &&
    STATX_INO == 0x100U && STATX_SIZE == 0x200U && STATX_BLOCKS == 0x400U &&
    STATX_BASIC_STATS == 0x7ffU && STATX_BTIME == 0x800U &&
    STATX_ALL == 0xfffU && STATX_MNT_ID == 0x1000U &&
    STATX_DIOALIGN == 0x2000U && STATX_MNT_ID_UNIQUE == 0x4000U &&
    STATX_SUBVOL == 0x8000U && STATX_WRITE_ATOMIC == 0x10000U,
    "x86 statx C++ request-mask macros");
static_assert(STATX_ATTR_COMPRESSED == 0x4 &&
    STATX_ATTR_IMMUTABLE == 0x10 && STATX_ATTR_APPEND == 0x20 &&
    STATX_ATTR_NODUMP == 0x40 && STATX_ATTR_ENCRYPTED == 0x800 &&
    STATX_ATTR_AUTOMOUNT == 0x1000 && STATX_ATTR_MOUNT_ROOT == 0x2000 &&
    STATX_ATTR_VERITY == 0x100000 && STATX_ATTR_DAX == 0x200000 &&
    STATX_ATTR_WRITE_ATOMIC == 0x400000,
    "x86 statx C++ attribute macros");
#ifdef STATX__RESERVED
#error "pinned musl does not publish STATX__RESERVED"
#endif
static_assert(sizeof(struct statx_timestamp) == 16 &&
    alignof(struct statx_timestamp) == 8 &&
    offsetof(struct statx_timestamp, tv_sec) == 0 &&
    offsetof(struct statx_timestamp, tv_nsec) == 8 &&
    offsetof(struct statx_timestamp, __pad) == 12,
    "x86 statx timestamp C++ layout");
static_assert(sizeof(struct statx) == 256 && alignof(struct statx) == 8,
    "x86 statx C++ layout size/alignment");
static_assert(offsetof(struct statx, stx_mask) == 0 &&
    offsetof(struct statx, stx_mode) == 28 &&
    offsetof(struct statx, stx_ino) == 32 &&
    offsetof(struct statx, stx_atime) == 64 &&
    offsetof(struct statx, stx_mtime) == 112 &&
    offsetof(struct statx, stx_mnt_id) == 144 &&
    offsetof(struct statx, stx_dio_mem_align) == 152 &&
    offsetof(struct statx, stx_dio_offset_align) == 156 &&
    offsetof(struct statx, stx_subvol) == 160 &&
    offsetof(struct statx, stx_atomic_write_segments_max) == 176 &&
    offsetof(struct statx, __pad2) == 184,
    "x86 statx C++ record offsets");
static_assert(__is_same(decltype(&statx), statx_function),
    "x86 statx C++ declaration");

statx_function crabc_x86_64_statx_header_abi_linkage = &statx;

int crabc_x86_64_stat_header_abi_probe_cpp()
{
    return S_ISDIR(static_cast<mode_t>(S_IFDIR)) ? 0 : 1;
}
