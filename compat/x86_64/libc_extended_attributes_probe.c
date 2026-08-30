/* Native Linux/x86-64 static extended-attribute C ABI fixture.
 *
 * The one project-header body runs first with pinned musl 1.2.6 and then with
 * the selected freestanding crabc archive. It exercises every Linux C xattr
 * entry point: path, no-follow-path, and descriptor set/get/list/remove forms.
 * Values are byte strings (including embedded NULs), caller buffers remain
 * caller-owned, and a zero-length value is distinct from a zero-size query.
 *
 * The no-follow calls deliberately address the regular fixture file rather
 * than a symbolic link. Whether a filesystem permits user xattrs on symlinks
 * is filesystem policy, not a property of l* syscall dispatch. A filesystem
 * which uniformly rejects the first path set operation with EOPNOTSUPP or
 * ENOSYS takes the deterministic unavailable branch (status 77).
 *
 * Fixture-local raw openat/close/unlink setup keeps the final binary's public
 * libc surface to xattr plus errno. This is not a general C filesystem or
 * startup claim.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

enum {
    CRABC_XATTR_LIST_CAPACITY = 512,
    CRABC_XATTR_UNTOUCHED = 0xa5,
    CRABC_XATTR_UNAVAILABLE = 77,
};

_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8,
    "x86 LP64 xattr sizes");
_Static_assert(SYS_openat == 257 && SYS_close == 3 && SYS_unlink == 87,
    "x86 fixture setup syscall numbers");
_Static_assert(SYS_setxattr == 188 && SYS_lsetxattr == 189 && SYS_fsetxattr == 190 &&
    SYS_getxattr == 191 && SYS_lgetxattr == 192 && SYS_fgetxattr == 193 &&
    SYS_listxattr == 194 && SYS_llistxattr == 195 && SYS_flistxattr == 196 &&
    SYS_removexattr == 197 && SYS_lremovexattr == 198 && SYS_fremovexattr == 199,
    "x86 xattr syscall numbers");
_Static_assert(AT_FDCWD == -100 && O_RDWR == 2 && O_CREAT == 0100 &&
    O_EXCL == 0200 && O_CLOEXEC == 02000000,
    "x86 fixture setup constants");
_Static_assert(XATTR_CREATE == 1 && XATTR_REPLACE == 2, "xattr flags");
_Static_assert(CRABC_TYPE_IS(__typeof__(&setxattr),
        int (*)(const char *, const char *, const void *, size_t, int)) &&
    CRABC_TYPE_IS(__typeof__(&lsetxattr),
        int (*)(const char *, const char *, const void *, size_t, int)) &&
    CRABC_TYPE_IS(__typeof__(&fsetxattr),
        int (*)(int, const char *, const void *, size_t, int)) &&
    CRABC_TYPE_IS(__typeof__(&getxattr),
        ssize_t (*)(const char *, const char *, void *, size_t)) &&
    CRABC_TYPE_IS(__typeof__(&lgetxattr),
        ssize_t (*)(const char *, const char *, void *, size_t)) &&
    CRABC_TYPE_IS(__typeof__(&fgetxattr),
        ssize_t (*)(int, const char *, void *, size_t)) &&
    CRABC_TYPE_IS(__typeof__(&listxattr), ssize_t (*)(const char *, char *, size_t)) &&
    CRABC_TYPE_IS(__typeof__(&llistxattr), ssize_t (*)(const char *, char *, size_t)) &&
    CRABC_TYPE_IS(__typeof__(&flistxattr), ssize_t (*)(int, char *, size_t)) &&
    CRABC_TYPE_IS(__typeof__(&removexattr), int (*)(const char *, const char *)) &&
    CRABC_TYPE_IS(__typeof__(&lremovexattr), int (*)(const char *, const char *)) &&
    CRABC_TYPE_IS(__typeof__(&fremovexattr), int (*)(int, const char *)),
    "selected xattr declarations");

enum xattr_form {
    XATTR_PATH,
    XATTR_NOFOLLOW_PATH,
    XATTR_DESCRIPTOR,
};

static long raw_syscall6(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5, long argument6)
{
    register long r10 __asm__("r10") = argument4;
    register long r8 __asm__("r8") = argument5;
    register long r9 __asm__("r9") = argument6;
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_open_record(const char *path)
{
    long result = raw_syscall6(SYS_openat, AT_FDCWD, (long)path,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600, 0, 0);

    if (result >= 0) return (int)result;
    errno = (int)-result;
    return -1;
}

static void raw_close(int descriptor)
{
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
}

static void raw_unlink(const char *path)
{
    (void)raw_syscall6(SYS_unlink, (long)path, 0, 0, 0, 0, 0);
}

static void fill(unsigned char *buffer, size_t length, unsigned char value)
{
    size_t index;

    for (index = 0; index < length; ++index) buffer[index] = value;
}

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index]) return 0;
    }
    return 1;
}

static int list_contains(const char *list, size_t length, const char *wanted)
{
    size_t offset = 0;
    size_t wanted_length = 0;

    while (wanted[wanted_length] != '\0') ++wanted_length;
    while (offset < length) {
        size_t entry_length = 0;

        while (offset + entry_length < length && list[offset + entry_length] != '\0') {
            ++entry_length;
        }
        if (offset + entry_length == length) return 0;
        if (entry_length == wanted_length &&
            bytes_equal((const unsigned char *)(list + offset),
                (const unsigned char *)wanted, wanted_length)) {
            return 1;
        }
        offset += entry_length + 1;
    }
    return 0;
}

static int set_for(enum xattr_form form, const char *path, int descriptor,
    const char *name, const void *value, size_t length, int flags)
{
    switch (form) {
    case XATTR_PATH:
        return setxattr(path, name, value, length, flags);
    case XATTR_NOFOLLOW_PATH:
        return lsetxattr(path, name, value, length, flags);
    case XATTR_DESCRIPTOR:
        return fsetxattr(descriptor, name, value, length, flags);
    }
    return -1;
}

static ssize_t get_for(enum xattr_form form, const char *path, int descriptor,
    const char *name, void *value, size_t length)
{
    switch (form) {
    case XATTR_PATH:
        return getxattr(path, name, value, length);
    case XATTR_NOFOLLOW_PATH:
        return lgetxattr(path, name, value, length);
    case XATTR_DESCRIPTOR:
        return fgetxattr(descriptor, name, value, length);
    }
    return -1;
}

static ssize_t list_for(enum xattr_form form, const char *path, int descriptor,
    char *list, size_t length)
{
    switch (form) {
    case XATTR_PATH:
        return listxattr(path, list, length);
    case XATTR_NOFOLLOW_PATH:
        return llistxattr(path, list, length);
    case XATTR_DESCRIPTOR:
        return flistxattr(descriptor, list, length);
    }
    return -1;
}

static int remove_for(enum xattr_form form, const char *path, int descriptor,
    const char *name)
{
    switch (form) {
    case XATTR_PATH:
        return removexattr(path, name);
    case XATTR_NOFOLLOW_PATH:
        return lremovexattr(path, name);
    case XATTR_DESCRIPTOR:
        return fremovexattr(descriptor, name);
    }
    return -1;
}

static int get_matches(enum xattr_form form, const char *path, int descriptor,
    const char *name, const unsigned char *wanted, size_t wanted_length)
{
    unsigned char buffer[32];
    ssize_t result;
    size_t index;

    result = get_for(form, path, descriptor, name, NULL, 0);
    if (result != (ssize_t)wanted_length) return 0;
    fill(buffer, sizeof(buffer), CRABC_XATTR_UNTOUCHED);
    result = get_for(form, path, descriptor, name, buffer, sizeof(buffer));
    if (result != (ssize_t)wanted_length ||
        !bytes_equal(buffer, wanted, wanted_length)) {
        return 0;
    }
    for (index = wanted_length; index < sizeof(buffer); ++index) {
        if (buffer[index] != CRABC_XATTR_UNTOUCHED) return 0;
    }
    return 1;
}

static int list_matches(enum xattr_form form, const char *path, int descriptor,
    const char *path_name, const char *nofollow_name, const char *fd_name,
    const char *empty_name, const char *flags_name)
{
    char list[CRABC_XATTR_LIST_CAPACITY];
    ssize_t required;
    ssize_t result;

    required = list_for(form, path, descriptor, NULL, 0);
    if (required <= 0 || required > (ssize_t)sizeof(list)) return 0;
    fill((unsigned char *)list, sizeof(list), CRABC_XATTR_UNTOUCHED);
    result = list_for(form, path, descriptor, list, sizeof(list));
    return result == required && list[result - 1] == '\0' &&
        list_contains(list, (size_t)result, path_name) &&
        list_contains(list, (size_t)result, nofollow_name) &&
        list_contains(list, (size_t)result, fd_name) &&
        list_contains(list, (size_t)result, empty_name) &&
        list_contains(list, (size_t)result, flags_name);
}

static int run_fixture(void)
{
    static const char path[] = "xattr-record";
    static const char path_name[] = "user.crabc-x86-c-path";
    static const char nofollow_name[] = "user.crabc-x86-c-nofollow";
    static const char fd_name[] = "user.crabc-x86-c-fd";
    static const char empty_name[] = "user.crabc-x86-c-empty";
    static const char flags_name[] = "user.crabc-x86-c-flags";
    static const char missing_name[] = "user.crabc-x86-c-missing";
    static const unsigned char path_value[] = {'p', 'a', '\0', 't', 'h'};
    static const unsigned char nofollow_value[] = {'n', 'o', '\0', 'f', 'o', 'l', 'l', 'o', 'w'};
    static const unsigned char fd_value[] = {'f', 'd', '\0', 'v', 'a', 'l', 'u', 'e'};
    static const unsigned char replacement_value[] = {'r', 'e', 'p', 'l', '\0', 'a', 'c', 'e', 'd'};
    unsigned char short_buffer[1];
    int descriptor = -1;
    int result = 0;

    descriptor = raw_open_record(path);
    if (descriptor < 0) return 10;

    if (set_for(XATTR_PATH, path, descriptor, path_name, path_value,
            sizeof(path_value), XATTR_CREATE) != 0) {
        if (errno == EOPNOTSUPP || errno == ENOSYS) {
            result = CRABC_XATTR_UNAVAILABLE;
            goto cleanup;
        }
        result = 11;
        goto cleanup;
    }
    if (set_for(XATTR_NOFOLLOW_PATH, path, descriptor, nofollow_name,
            nofollow_value, sizeof(nofollow_value), XATTR_CREATE) != 0 ||
        set_for(XATTR_DESCRIPTOR, path, descriptor, fd_name, fd_value,
            sizeof(fd_value), XATTR_CREATE) != 0 ||
        setxattr(path, empty_name, NULL, 0, XATTR_CREATE) != 0) {
        result = 12;
        goto cleanup;
    }

    if (!get_matches(XATTR_PATH, path, descriptor, path_name, path_value,
            sizeof(path_value)) ||
        !get_matches(XATTR_NOFOLLOW_PATH, path, descriptor, nofollow_name,
            nofollow_value, sizeof(nofollow_value)) ||
        !get_matches(XATTR_DESCRIPTOR, path, descriptor, fd_name, fd_value,
            sizeof(fd_value)) ||
        get_for(XATTR_PATH, path, descriptor, empty_name, NULL, 0) != 0) {
        result = 13;
        goto cleanup;
    }

    fill(short_buffer, sizeof(short_buffer), CRABC_XATTR_UNTOUCHED);
    if (get_for(XATTR_PATH, path, descriptor, path_name, short_buffer,
            sizeof(short_buffer)) != -1 || errno != ERANGE) {
        result = 14;
        goto cleanup;
    }

    if (setxattr(path, flags_name, "initial", sizeof("initial") - 1,
            XATTR_CREATE) != 0 ||
        setxattr(path, flags_name, "again", sizeof("again") - 1,
            XATTR_CREATE) != -1 || errno != EEXIST ||
        setxattr(path, flags_name, replacement_value, sizeof(replacement_value),
            XATTR_REPLACE) != 0 ||
        setxattr(path, missing_name, "missing", sizeof("missing") - 1,
            XATTR_REPLACE) != -1 || errno != ENODATA ||
        setxattr(path, missing_name, "invalid", sizeof("invalid") - 1, 4) != -1 ||
        errno != EINVAL ||
        !get_matches(XATTR_PATH, path, descriptor, flags_name, replacement_value,
            sizeof(replacement_value))) {
        result = 15;
        goto cleanup;
    }

    if (!list_matches(XATTR_PATH, path, descriptor, path_name, nofollow_name,
            fd_name, empty_name, flags_name) ||
        !list_matches(XATTR_NOFOLLOW_PATH, path, descriptor, path_name,
            nofollow_name, fd_name, empty_name, flags_name) ||
        !list_matches(XATTR_DESCRIPTOR, path, descriptor, path_name,
            nofollow_name, fd_name, empty_name, flags_name)) {
        result = 16;
        goto cleanup;
    }
    fill(short_buffer, sizeof(short_buffer), CRABC_XATTR_UNTOUCHED);
    if (listxattr(path, (char *)short_buffer, sizeof(short_buffer)) != -1 ||
        errno != ERANGE) {
        result = 17;
        goto cleanup;
    }

    if (remove_for(XATTR_PATH, path, descriptor, path_name) != 0 ||
        remove_for(XATTR_NOFOLLOW_PATH, path, descriptor, nofollow_name) != 0 ||
        remove_for(XATTR_DESCRIPTOR, path, descriptor, fd_name) != 0 ||
        removexattr(path, empty_name) != 0 || removexattr(path, flags_name) != 0) {
        result = 18;
        goto cleanup;
    }
    if (get_for(XATTR_PATH, path, descriptor, path_name, NULL, 0) != -1 ||
        errno != ENODATA ||
        get_for(XATTR_NOFOLLOW_PATH, path, descriptor, nofollow_name, NULL, 0) != -1 ||
        errno != ENODATA ||
        get_for(XATTR_DESCRIPTOR, path, descriptor, fd_name, NULL, 0) != -1 ||
        errno != ENODATA || removexattr(path, path_name) != -1 || errno != ENODATA) {
        result = 19;
    }

cleanup:
    raw_close(descriptor);
    raw_unlink(path);
    return result;
}

#ifdef CRABC_EXTENDED_ATTRIBUTES_FREESTANDING
int crabc_x86_64_extended_attributes_probe(void)
{
    return run_fixture();
}
#else
int main(void)
{
    return run_fixture();
}
#endif
