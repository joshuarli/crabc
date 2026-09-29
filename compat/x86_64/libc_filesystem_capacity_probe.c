/* Static crabc-libc x86-64 freestanding filesystem-capacity fixture.
 *
 * This project-header C body executes first through pinned musl 1.2.6 and
 * then through one `-nostdlib -static` executable linked solely with the
 * selected crabc archive. Raw Linux calls create, inspect, and remove one
 * temporary regular file and a directory descriptor; the four
 * filesystem-capacity entry points are the only candidate C calls. Case
 * records expose the exercised path, descriptor, capacity-mapping, and error
 * boundaries to the paired pinned-musl/candidate runner.
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

_Static_assert(SYS_write == 1 && SYS_open == 2 && SYS_close == 3 && SYS_dup == 32 &&
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
    static const char prefix[] = ".work/x86_64/tmp/crabc-x86-filesystem-capacity-";
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

static int record(const char *line, size_t length)
{
    return raw3(SYS_write, 1, (long)(void *)line, (long)length) == (long)length;
}

#define RECORD(line) record(line, sizeof(line) - 1)

static void fill_bytes(void *record, size_t length, unsigned char value)
{
    unsigned char *bytes = record;
    size_t index;
    for (index = 0; index < length; ++index)
        bytes[index] = value;
}

static int bytes_equal(const void *record, size_t length, unsigned char value)
{
    const unsigned char *bytes = record;
    size_t index;
    for (index = 0; index < length; ++index)
        if (bytes[index] != value)
            return 0;
    return 1;
}

static int path_error(const char *path, int expected)
{
    struct statfs capacity;
    struct statvfs view;
    fill_bytes(&capacity, sizeof(capacity), 0xa5);
    fill_bytes(&view, sizeof(view), 0xa5);
    errno = EDOM;
    if (statfs(path, &capacity) != -1 || errno != expected ||
        !bytes_equal(&capacity, sizeof(capacity), 0))
        return 0;
    errno = E2BIG;
    return statvfs(path, &view) == -1 && errno == expected &&
        bytes_equal(&view, sizeof(view), 0xa5);
}

static int fd_error(int descriptor, int expected)
{
    struct statfs capacity;
    struct statvfs view;
    fill_bytes(&capacity, sizeof(capacity), 0xa5);
    fill_bytes(&view, sizeof(view), 0xa5);
    errno = EDOM;
    if (fstatfs(descriptor, &capacity) != -1 || errno != expected ||
        !bytes_equal(&capacity, sizeof(capacity), 0))
        return 0;
    errno = E2BIG;
    return fstatvfs(descriptor, &view) == -1 && errno == expected &&
        bytes_equal(&view, sizeof(view), 0xa5);
}

/* Accounting counters can change between two syscalls on a busy filesystem. */
static int same_statfs_stable_fields(const struct statfs *left,
    const struct statfs *right)
{
    size_t index;
    if (left->f_type != right->f_type || left->f_bsize != right->f_bsize ||
        left->f_namelen != right->f_namelen || left->f_frsize != right->f_frsize ||
        left->f_flags != right->f_flags)
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

static int statfs_capacity_is_sensible(const struct statfs *value)
{
    return value->f_bsize != 0 && value->f_blocks >= value->f_bfree &&
        value->f_files >= value->f_ffree;
}

/* Compare stable conversion fields; each call validates its own live counts. */
static int statvfs_mapping_is_consistent(const struct statvfs *value,
    const struct statfs *source)
{
    unsigned long fragment_size = source->f_frsize != 0 ? source->f_frsize :
        source->f_bsize;
    size_t index;
    for (index = 0; index < 5; ++index)
        if (value->__reserved[index] != 0)
            return 0;
    return value->f_bsize == source->f_bsize &&
        value->f_frsize == fragment_size &&
        value->f_favail == value->f_ffree &&
        value->f_fsid == (unsigned long)source->f_fsid.__val[0] &&
        value->f_flag == source->f_flags &&
        value->f_namemax == source->f_namelen &&
        value->f_type == (unsigned int)source->f_type;
}

static int same_statvfs_stable_fields(const struct statvfs *left,
    const struct statvfs *right)
{
    return left->f_bsize == right->f_bsize && left->f_frsize == right->f_frsize &&
        left->f_fsid == right->f_fsid && left->f_flag == right->f_flag &&
        left->f_namemax == right->f_namemax && left->f_type == right->f_type;
}

static int statvfs_capacity_is_sensible(const struct statvfs *view)
{
    return view->f_bsize != 0 && view->f_frsize != 0 &&
        view->f_blocks >= view->f_bfree && view->f_files >= view->f_ffree;
}

int crabc_x86_64_filesystem_capacity_probe(void)
{
    char path[96] = { 0 };
    char missing[104] = { 0 };
    char nondirectory[104] = { 0 };
    struct statfs path_statfs;
    struct statfs fd_statfs;
    struct statvfs path_statvfs;
    struct statvfs fd_statvfs;
    int descriptor = -1;
    int directory = -1;
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
    index = 0;
    while (path[index] != '\0') {
        if (index + 7 >= sizeof(nondirectory))
            return 22;
        nondirectory[index] = path[index];
        ++index;
    }
    nondirectory[index++] = '/';
    nondirectory[index++] = 'c';
    nondirectory[index++] = 'h';
    nondirectory[index++] = 'i';
    nondirectory[index++] = 'l';
    nondirectory[index++] = 'd';
    nondirectory[index] = '\0';
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
        fstatfs(descriptor, &fd_statfs) != 0 ||
        !same_statfs_stable_fields(&path_statfs, &fd_statfs) ||
        !statfs_tail_is_zero(&path_statfs) || !statfs_tail_is_zero(&fd_statfs) ||
        !statfs_capacity_is_sensible(&path_statfs) ||
        !statfs_capacity_is_sensible(&fd_statfs)) {
        result = 13;
        goto cleanup;
    }
    errno = EDOM;
    if (statvfs(path, &path_statvfs) != 0 || errno != EDOM ||
        fstatvfs(descriptor, &fd_statvfs) != 0 ||
        !statvfs_mapping_is_consistent(&path_statvfs, &path_statfs) ||
        !statvfs_mapping_is_consistent(&fd_statvfs, &fd_statfs) ||
        !same_statvfs_stable_fields(&path_statvfs, &fd_statvfs) ||
        !statvfs_capacity_is_sensible(&path_statvfs) ||
        !statvfs_capacity_is_sensible(&fd_statvfs) || !RECORD("regular.path-fd\n")) {
        result = 14;
        goto cleanup;
    }
    directory = (int)raw3(SYS_open, (long)(void *)".", O_RDONLY | O_DIRECTORY, 0);
    if (directory < 0) {
        result = 15;
        goto cleanup;
    }
    errno = ERANGE;
    if (statfs(".", &path_statfs) != 0 || errno != ERANGE ||
        fstatfs(directory, &fd_statfs) != 0 ||
        !same_statfs_stable_fields(&path_statfs, &fd_statfs) ||
        !statfs_tail_is_zero(&path_statfs) || !statfs_tail_is_zero(&fd_statfs) ||
        !statfs_capacity_is_sensible(&path_statfs) ||
        !statfs_capacity_is_sensible(&fd_statfs)) {
        result = 16;
        goto cleanup;
    }
    errno = EDOM;
    if (statvfs(".", &path_statvfs) != 0 || errno != EDOM ||
        fstatvfs(directory, &fd_statvfs) != 0 ||
        !statvfs_mapping_is_consistent(&path_statvfs, &path_statfs) ||
        !statvfs_mapping_is_consistent(&fd_statvfs, &fd_statfs) ||
        !same_statvfs_stable_fields(&path_statvfs, &fd_statvfs) ||
        !statvfs_capacity_is_sensible(&path_statvfs) ||
        !statvfs_capacity_is_sensible(&fd_statvfs) || !RECORD("directory.path-fd\n")) {
        result = 17;
        goto cleanup;
    }
    if (!path_error("", ENOENT) || !RECORD("empty-path.ENOENT\n")) {
        result = 18;
        goto cleanup;
    }
    if (!path_error(missing, ENOENT) || !RECORD("missing-path.ENOENT\n")) {
        result = 19;
        goto cleanup;
    }
    if (!path_error(nondirectory, ENOTDIR) || !RECORD("nondirectory-path.ENOTDIR\n")) {
        result = 20;
        goto cleanup;
    }
    closed_descriptor = (int)raw1(SYS_dup, descriptor);
    if (closed_descriptor < 0 || close_fd(closed_descriptor) != 0) {
        result = 21;
        goto cleanup;
    }
    if (!fd_error(closed_descriptor, EBADF) || !RECORD("closed-fd.EBADF\n")) {
        result = 22;
        goto cleanup;
    }
    if (!fd_error(-1, EBADF) || !RECORD("negative-fd.EBADF\n")) {
        result = 23;
        goto cleanup;
    }
    if (raw1(SYS_unlink, (long)(void *)path) < 0) {
        result = 24;
        goto cleanup;
    }
    path_owned = 0;
    errno = ERANGE;
    if (fstatfs(descriptor, &fd_statfs) != 0 || errno != ERANGE ||
        fstatvfs(descriptor, &fd_statvfs) != 0 ||
        !statfs_tail_is_zero(&fd_statfs) ||
        !statfs_capacity_is_sensible(&fd_statfs) ||
        !statvfs_mapping_is_consistent(&fd_statvfs, &fd_statfs) ||
        !statvfs_capacity_is_sensible(&fd_statvfs) ||
        !path_error(path, ENOENT) || !RECORD("unlinked-file.fd-survives-path-ENOENT\n")) {
        result = 25;
        goto cleanup;
    }

cleanup:
    if (descriptor >= 0 && close_fd(descriptor) != 0 && result == 0)
        result = 26;
    if (directory >= 0 && close_fd(directory) != 0 && result == 0)
        result = 27;
    if (path_owned && raw1(SYS_unlink, (long)(void *)path) < 0 && result == 0)
        result = 28;
    return result;
}

#ifndef CRABC_FILESYSTEM_CAPACITY_FREESTANDING
int main(void)
{
    return crabc_x86_64_filesystem_capacity_probe();
}
#endif
