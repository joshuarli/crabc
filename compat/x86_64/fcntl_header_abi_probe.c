/* Source-only Linux/x86-64 <fcntl.h> declaration/value/layout probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#define _GNU_SOURCE 1
#define _LARGEFILE64_SOURCE 1
#include <stddef.h>
#include <fcntl.h>

_Static_assert(sizeof(off_t) == 8 && sizeof(mode_t) == 4 && sizeof(pid_t) == 4,
    "x86 fcntl scalar widths");
_Static_assert(sizeof(struct flock) == 32 && _Alignof(struct flock) == 8,
    "x86 struct flock size/alignment");
_Static_assert(offsetof(struct flock, l_type) == 0 &&
    offsetof(struct flock, l_whence) == 2 &&
    offsetof(struct flock, l_start) == 8 &&
    offsetof(struct flock, l_len) == 16 &&
    offsetof(struct flock, l_pid) == 24, "x86 struct flock offsets");
_Static_assert(sizeof(struct f_owner_ex) == 8 &&
    offsetof(struct f_owner_ex, pid) == 4, "x86 f_owner_ex layout");
_Static_assert(sizeof(struct file_handle) == 8 &&
    offsetof(struct file_handle, f_handle) == 8, "x86 file_handle layout");

_Static_assert(O_RDONLY == 0 && O_WRONLY == 1 && O_RDWR == 2,
    "x86 access modes");
_Static_assert(O_CREAT == 0100 && O_EXCL == 0200 && O_NOCTTY == 0400 &&
    O_TRUNC == 01000 && O_APPEND == 02000 && O_NONBLOCK == 04000,
    "x86 basic open flags");
_Static_assert(O_DSYNC == 010000 && O_SYNC == 04010000 &&
    O_DIRECTORY == 0200000 && O_NOFOLLOW == 0400000 &&
    O_CLOEXEC == 02000000, "x86 open flags");
_Static_assert(O_DIRECT == 040000 && O_LARGEFILE == 0100000 &&
    O_NOATIME == 01000000 && O_PATH == 010000000 &&
    O_TMPFILE == 020200000 && O_ACCMODE == (03|O_PATH),
    "x86 Linux open extensions");
_Static_assert(F_DUPFD == 0 && F_GETFD == 1 && F_SETFD == 2 &&
    F_GETFL == 3 && F_SETFL == 4 && F_GETLK == 5 && F_SETLK == 6 &&
    F_SETLKW == 7 && F_SETOWN == 8 && F_GETOWN == 9 &&
    F_SETSIG == 10 && F_GETSIG == 11 && F_GETOWNER_UIDS == 17,
    "x86 fcntl commands");
_Static_assert(AT_FDCWD == -100 && AT_EMPTY_PATH == 0x1000 &&
    AT_NO_AUTOMOUNT == 0x800 && AT_RECURSIVE == 0x8000,
    "x86 at flags");
_Static_assert(F_SETLEASE == 1024 && F_CANCELLK == 1029 &&
    F_SETPIPE_SZ == 1031 && F_GET_SEALS == 1034 &&
    F_SET_FILE_RW_HINT == 1038, "x86 GNU fcntl commands");
_Static_assert(F_SEAL_SEAL == 1 && F_SEAL_FUTURE_WRITE == 0x10 &&
    DN_ACCESS == 1 && DN_ATTRIB == 0x20 && DN_MULTISHOT == 0x80000000U,
    "x86 seal and dnotify flags");
_Static_assert(F_GETLK64 == F_GETLK && sizeof(off64_t) == sizeof(off_t),
    "x86 large-file aliases");

static int (*open_signature)(const char *, int, ...) = open;
static int (*openat_signature)(int, const char *, int, ...) = openat;
static int (*creat_signature)(const char *, mode_t) = creat;
static int (*fcntl_signature)(int, int, ...) = fcntl;
static int (*lockf_signature)(int, int, off_t) = lockf;
static int (*lockf64_signature)(int, int, off64_t) = lockf64;
static int (*fallocate_signature)(int, int, off_t, off_t) = fallocate;
static int (*posix_fallocate_signature)(int, off_t, off_t) = posix_fallocate;
static int (*posix_fallocate64_signature)(int, off64_t, off64_t) = posix_fallocate64;

int crabc_x86_64_fcntl_header_abi_probe(void)
{
    struct flock value = { 0 };
    (void)open_signature;
    (void)openat_signature;
    (void)creat_signature;
    (void)fcntl_signature;
    (void)lockf_signature;
    (void)lockf64_signature;
    (void)fallocate_signature;
    (void)posix_fallocate_signature;
    (void)posix_fallocate64_signature;
    return value.l_type;
}
