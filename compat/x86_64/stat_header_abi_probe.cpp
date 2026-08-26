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

int crabc_x86_64_stat_header_abi_probe_cpp()
{
    return S_ISDIR(static_cast<mode_t>(S_IFDIR)) ? 0 : 1;
}
