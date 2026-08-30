/* C++ source-only companion for the x86-64 <fcntl.h> ABI probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#define _GNU_SOURCE 1
#define _LARGEFILE64_SOURCE 1
#include <stddef.h>
#include <fcntl.h>

static_assert(sizeof(struct flock) == 32 && alignof(struct flock) == 8,
    "x86 struct flock C++ size/alignment");
static_assert(offsetof(struct flock, l_start) == 8 &&
    offsetof(struct flock, l_len) == 16 &&
    offsetof(struct flock, l_pid) == 24, "x86 struct flock C++ offsets");
static_assert(sizeof(struct f_owner_ex) == 8 &&
    offsetof(struct f_owner_ex, pid) == 4, "x86 owner C++ layout");
static_assert(sizeof(struct file_handle) == 8 &&
    offsetof(struct file_handle, f_handle) == 8, "x86 handle C++ layout");
static_assert(O_NOFOLLOW == 0400000 && O_DIRECTORY == 0200000 &&
    O_DIRECT == 040000 && O_ACCMODE == (03|O_PATH),
    "x86 C++ open flags");
static_assert(F_GETLK == 5 && F_SETLK == 6 && F_SETLKW == 7 &&
    F_GETOWNER_UIDS == 17 && F_DUPFD_CLOEXEC == 1030,
    "x86 C++ fcntl commands");
static_assert(AT_EMPTY_PATH == 0x1000 && F_SEAL_WRITE == 8 &&
    SPLICE_F_GIFT == 8, "x86 C++ GNU flags");

using open_function = int (*)(const char *, int, ...);
using openat_function = int (*)(int, const char *, int, ...);
using creat_function = int (*)(const char *, mode_t);
using fcntl_function = int (*)(int, int, ...);
using lockf_function = int (*)(int, int, off64_t);
using posix_fallocate_function = int (*)(int, off_t, off_t);
using posix_fallocate64_function = int (*)(int, off64_t, off64_t);
static_assert(__is_same(decltype(&open), open_function),
    "x86 C++ open declaration");
static_assert(__is_same(decltype(&openat), openat_function),
    "x86 C++ openat declaration");
static_assert(__is_same(decltype(&creat), creat_function),
    "x86 C++ creat declaration");
static_assert(__is_same(decltype(&fcntl), fcntl_function),
    "x86 C++ fcntl declaration");
static_assert(__is_same(decltype(&lockf64), lockf_function),
    "x86 C++ lockf64 declaration");
static_assert(__is_same(decltype(&posix_fallocate), posix_fallocate_function),
    "x86 C++ posix_fallocate declaration");
static_assert(__is_same(decltype(&posix_fallocate64), posix_fallocate64_function),
    "x86 C++ posix_fallocate64 declaration");

int crabc_x86_64_fcntl_header_abi_probe_cpp()
{
    struct flock value{};
    value.l_type = F_RDLCK;
    return value.l_type;
}
