/* Static crabc-libc x86-64 freestanding filesystem-capacity fixture.
 *
 * This project-header C body executes first through pinned musl 1.2.6 and
 * then through one `-nostdlib -static` executable linked solely with the
 * selected crabc archive. Raw Linux calls create, inspect, and remove one
 * temporary regular file; the four filesystem-capacity entry points are the
 * only candidate C calls. It proves direct statfs records, musl's statvfs
 * conversion, success stale-errno preservation, and pathname/closed-fd errno
 * behavior. It is not filesystem policy, pathname support, CRT, pthread/TLS
 * lifecycle, loader, sysroot, or public x86-64 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>

_Static_assert(SYS_open == 2 && SYS_close == 3 && SYS_dup == 32 &&
    SYS_getpid == 39 && SYS_unlink == 87 && SYS_statfs == 137 &&
    SYS_fstatfs == 138, "x86 filesystem-capacity fixture syscall numbers");
_Static_assert(sizeof(struct statfs) == 120 && _Alignof(struct statfs) == 8,
    "x86 statfs record layout");
_Static_assert(sizeof(struct statvfs) == 112 && _Alignof(struct statvfs) == 8,
    "x86 statvfs record layout");
_Static_assert(__builtin_types_compatible_p(__typeof__(&statfs),
    int (*)(const char *, struct statfs *)), "statfs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fstatfs),
    int (*)(int, struct statfs *)), "fstatfs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&statvfs),
    int (*)(const char *, struct statvfs *)), "statvfs declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fstatvfs),
    int (*)(int, struct statvfs *)), "fstatvfs declaration");

static long raw0(long number)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw1(long number, long argument_one)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one) : "rcx", "r11", "memory");
    return result;
}

static long raw3(long number, long argument_one, long argument_two,
    long argument_three)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three) : "rcx", "r11", "memory");
    return result;
}

static int make_path(char *output, size_t capacity, long process_id)
{
    static const char prefix[] = "/tmp/crabc-x86-filesystem-capacity-";
    char digits[20];
    size_t length = 0;
    size_t prefix_length = 0;
    size_t digit_count = 0;
    unsigned long identifier;

    if (process_id <= 0)
        return -1;
    identifier = (unsigned long)process_id;
    while (prefix[prefix_length] != '\0') {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = prefix[prefix_length++];
    }
    do {
        if (digit_count == sizeof(digits))
            return -1;
        digits[digit_count++] = (char)('0' + identifier % 10);
        identifier /= 10;
    } while (identifier != 0);
    while (digit_count != 0) {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = digits[--digit_count];
    }
    output[length] = '\0';
    return 0;
}

static int close_fd(int descriptor)
{
    return descriptor >= 0 && raw1(SYS_close, descriptor) < 0 ? -1 : 0;
}

static int same_statfs(const struct statfs *left, const struct statfs *right)
{
    size_t index;
    if (left->f_type != right->f_type || left->f_bsize != right->f_bsize ||
        left->f_blocks != right->f_blocks || left->f_bfree != right->f_bfree ||
        left->f_bavail != right->f_bavail || left->f_files != right->f_files ||
        left->f_ffree != right->f_ffree || left->f_namelen != right->f_namelen ||
        left->f_frsize != right->f_frsize || left->f_flags != right->f_flags)
        return 0;
    for (index = 0; index < 2; ++index)
        if (left->f_fsid.__val[index] != right->f_fsid.__val[index])
            return 0;
    for (index = 0; index < 4; ++index)
        if (left->f_spare[index] != right->f_spare[index])
            return 0;
    return 1;
}

static int statfs_tail_is_zero(const struct statfs *value)
{
    size_t index;
    for (index = 0; index < 4; ++index)
        if (value->f_spare[index] != 0)
            return 0;
    return 1;
}

static int statvfs_matches_statfs(const struct statvfs *value,
    const struct statfs *source)
{
    unsigned long fragment_size = source->f_frsize != 0 ? source->f_frsize :
        source->f_bsize;
    size_t index;
    for (index = 0; index < 5; ++index)
        if (value->__reserved[index] != 0)
            return 0;
    return value->f_bsize == source->f_bsize &&
        value->f_frsize == fragment_size && value->f_blocks == source->f_blocks &&
        value->f_bfree == source->f_bfree && value->f_bavail == source->f_bavail &&
        value->f_files == source->f_files && value->f_ffree == source->f_ffree &&
        value->f_favail == source->f_ffree &&
        value->f_fsid == (unsigned long)source->f_fsid.__val[0] &&
        value->f_flag == source->f_flags &&
        value->f_namemax == source->f_namelen &&
        value->f_type == (unsigned int)source->f_type;
}

static int same_statvfs(const struct statvfs *left, const struct statvfs *right)
{
    return left->f_bsize == right->f_bsize && left->f_frsize == right->f_frsize &&
        left->f_blocks == right->f_blocks && left->f_bfree == right->f_bfree &&
        left->f_bavail == right->f_bavail && left->f_files == right->f_files &&
        left->f_ffree == right->f_ffree && left->f_favail == right->f_favail &&
        left->f_fsid == right->f_fsid && left->f_flag == right->f_flag &&
        left->f_namemax == right->f_namemax && left->f_type == right->f_type;
}

int crabc_x86_64_filesystem_capacity_probe(void)
{
    char path[96] = { 0 };
    char missing[104] = { 0 };
    struct statfs path_statfs;
    struct statfs fd_statfs;
    struct statvfs path_statvfs;
    struct statvfs fd_statvfs;
    int descriptor = -1;
    int closed_descriptor = -1;
    int path_owned = 0;
    int result = 0;
    size_t index = 0;

    if (make_path(path, sizeof(path), raw0(SYS_getpid)) != 0)
        return 10;
    while (path[index] != '\0') {
        if (index + 2 >= sizeof(missing))
            return 11;
        missing[index] = path[index];
        ++index;
    }
    missing[index++] = '-';
    missing[index++] = 'x';
    missing[index] = '\0';
    descriptor = (int)raw3(SYS_open, (long)(void *)path,
        O_CREAT | O_EXCL | O_RDWR, 0600);
    if (descriptor < 0)
        return 12;
    path_owned = 1;

    for (index = 0; index < 4; ++index) {
        path_statfs.f_spare[index] = ~(unsigned long)0;
        fd_statfs.f_spare[index] = ~(unsigned long)0;
    }
    errno = ERANGE;
    if (statfs(path, &path_statfs) != 0 || errno != ERANGE ||
        fstatfs(descriptor, &fd_statfs) != 0 || !same_statfs(&path_statfs, &fd_statfs) ||
        !statfs_tail_is_zero(&path_statfs) || !statfs_tail_is_zero(&fd_statfs)) {
        result = 13;
        goto cleanup;
    }
    errno = EDOM;
    if (statvfs(path, &path_statvfs) != 0 || errno != EDOM ||
        fstatvfs(descriptor, &fd_statvfs) != 0 ||
        !statvfs_matches_statfs(&path_statvfs, &path_statfs) ||
        !statvfs_matches_statfs(&fd_statvfs, &fd_statfs) ||
        !same_statvfs(&path_statvfs, &fd_statvfs)) {
        result = 14;
        goto cleanup;
    }
    errno = E2BIG;
    if (statfs(missing, &path_statfs) != -1 || errno != ENOENT) {
        result = 15;
        goto cleanup;
    }
    errno = ERANGE;
    if (statvfs(missing, &path_statvfs) != -1 || errno != ENOENT) {
        result = 16;
        goto cleanup;
    }
    closed_descriptor = (int)raw1(SYS_dup, descriptor);
    if (closed_descriptor < 0 || close_fd(closed_descriptor) != 0) {
        result = 17;
        goto cleanup;
    }
    errno = EDOM;
    if (fstatfs(closed_descriptor, &fd_statfs) != -1 || errno != EBADF) {
        result = 18;
        goto cleanup;
    }
    errno = E2BIG;
    if (fstatvfs(closed_descriptor, &fd_statvfs) != -1 || errno != EBADF) {
        result = 19;
        goto cleanup;
    }

cleanup:
    if (descriptor >= 0 && close_fd(descriptor) != 0 && result == 0)
        result = 20;
    if (path_owned && raw1(SYS_unlink, (long)(void *)path) < 0 && result == 0)
        result = 21;
    return result;
}

#ifndef CRABC_FILESYSTEM_CAPACITY_FREESTANDING
int main(void)
{
    return crabc_x86_64_filesystem_capacity_probe();
}
#endif
