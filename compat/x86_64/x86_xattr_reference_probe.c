/* Pinned-musl/raw Linux/x86-64 extended-attribute ABI and behavior reference. */
#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

_Static_assert(sizeof(size_t) == 8, "x86 size_t width");
_Static_assert(sizeof(ssize_t) == 8, "x86 ssize_t width");
_Static_assert(SYS_setxattr == 188, "x86 setxattr syscall number");
_Static_assert(SYS_lsetxattr == 189, "x86 lsetxattr syscall number");
_Static_assert(SYS_fsetxattr == 190, "x86 fsetxattr syscall number");
_Static_assert(SYS_getxattr == 191, "x86 getxattr syscall number");
_Static_assert(SYS_lgetxattr == 192, "x86 lgetxattr syscall number");
_Static_assert(SYS_fgetxattr == 193, "x86 fgetxattr syscall number");
_Static_assert(SYS_listxattr == 194, "x86 listxattr syscall number");
_Static_assert(SYS_llistxattr == 195, "x86 llistxattr syscall number");
_Static_assert(SYS_flistxattr == 196, "x86 flistxattr syscall number");
_Static_assert(SYS_removexattr == 197, "x86 removexattr syscall number");
_Static_assert(SYS_lremovexattr == 198, "x86 lremovexattr syscall number");
_Static_assert(SYS_fremovexattr == 199, "x86 fremovexattr syscall number");
_Static_assert(XATTR_CREATE == 1, "xattr create flag");
_Static_assert(XATTR_REPLACE == 2, "xattr replace flag");

enum xattr_form {
    XATTR_PATH,
    XATTR_NOFOLLOW_PATH,
    XATTR_DESCRIPTOR,
};

struct result {
    long value;
    int error;
};

static struct result call_set(enum xattr_form form, const char *path, int fd,
                              const char *name, const void *value, size_t length,
                              unsigned flags, int raw)
{
    struct result result;

    errno = 0;
    switch (form) {
    case XATTR_PATH:
        result.value = raw ? syscall(SYS_setxattr, path, name, value, length, flags)
                           : setxattr(path, name, value, length, flags);
        break;
    case XATTR_NOFOLLOW_PATH:
        result.value = raw ? syscall(SYS_lsetxattr, path, name, value, length, flags)
                           : lsetxattr(path, name, value, length, flags);
        break;
    case XATTR_DESCRIPTOR:
        result.value = raw ? syscall(SYS_fsetxattr, fd, name, value, length, flags)
                           : fsetxattr(fd, name, value, length, flags);
        break;
    }
    result.error = errno;
    return result;
}

static struct result call_get(enum xattr_form form, const char *path, int fd,
                              const char *name, void *value, size_t length, int raw)
{
    struct result result;

    errno = 0;
    switch (form) {
    case XATTR_PATH:
        result.value = raw ? syscall(SYS_getxattr, path, name, value, length)
                           : getxattr(path, name, value, length);
        break;
    case XATTR_NOFOLLOW_PATH:
        result.value = raw ? syscall(SYS_lgetxattr, path, name, value, length)
                           : lgetxattr(path, name, value, length);
        break;
    case XATTR_DESCRIPTOR:
        result.value = raw ? syscall(SYS_fgetxattr, fd, name, value, length)
                           : fgetxattr(fd, name, value, length);
        break;
    }
    result.error = errno;
    return result;
}

static struct result call_list(enum xattr_form form, const char *path, int fd,
                               char *list, size_t length, int raw)
{
    struct result result;

    errno = 0;
    switch (form) {
    case XATTR_PATH:
        result.value = raw ? syscall(SYS_listxattr, path, list, length)
                           : listxattr(path, list, length);
        break;
    case XATTR_NOFOLLOW_PATH:
        result.value = raw ? syscall(SYS_llistxattr, path, list, length)
                           : llistxattr(path, list, length);
        break;
    case XATTR_DESCRIPTOR:
        result.value = raw ? syscall(SYS_flistxattr, fd, list, length)
                           : flistxattr(fd, list, length);
        break;
    }
    result.error = errno;
    return result;
}

static struct result call_remove(enum xattr_form form, const char *path, int fd,
                                 const char *name, int raw)
{
    struct result result;

    errno = 0;
    switch (form) {
    case XATTR_PATH:
        result.value = raw ? syscall(SYS_removexattr, path, name)
                           : removexattr(path, name);
        break;
    case XATTR_NOFOLLOW_PATH:
        result.value = raw ? syscall(SYS_lremovexattr, path, name)
                           : lremovexattr(path, name);
        break;
    case XATTR_DESCRIPTOR:
        result.value = raw ? syscall(SYS_fremovexattr, fd, name)
                           : fremovexattr(fd, name);
        break;
    }
    result.error = errno;
    return result;
}

static int list_contains(const char *list, size_t length, const char *name)
{
    size_t offset = 0;
    size_t wanted = strlen(name);

    while (offset < length) {
        const char *entry = list + offset;
        const char *terminator = memchr(entry, '\0', length - offset);
        size_t entry_length;

        if (terminator == NULL) return 0;
        entry_length = (size_t)(terminator - entry);
        if (entry_length == wanted && memcmp(entry, name, wanted) == 0) return 1;
        offset += entry_length + 1;
    }
    return 0;
}

static int verify_get_pair(enum xattr_form form, const char *path, int fd,
                           const char *musl_name, const unsigned char *musl_value,
                           size_t musl_length, const char *raw_name,
                           const unsigned char *raw_value, size_t raw_length)
{
    unsigned char musl_buffer[32], raw_buffer[32];
    struct result musl, raw;

    musl = call_get(form, path, fd, musl_name, NULL, 0, 0);
    raw = call_get(form, path, fd, raw_name, NULL, 0, 1);
    if (musl.value != (long)musl_length || raw.value != (long)raw_length) return 0;

    memset(musl_buffer, 0xa5, sizeof(musl_buffer));
    memset(raw_buffer, 0xa5, sizeof(raw_buffer));
    musl = call_get(form, path, fd, musl_name, musl_buffer, sizeof(musl_buffer), 0);
    raw = call_get(form, path, fd, raw_name, raw_buffer, sizeof(raw_buffer), 1);
    return musl.value == (long)musl_length && raw.value == (long)raw_length &&
           memcmp(musl_buffer, musl_value, musl_length) == 0 &&
           memcmp(raw_buffer, raw_value, raw_length) == 0 &&
           musl_buffer[musl_length] == 0xa5 && raw_buffer[raw_length] == 0xa5;
}

static int verify_list_pair(enum xattr_form form, const char *path, int fd,
                            const char *musl_name, const char *raw_name)
{
    char musl_list[512], raw_list[512];
    long musl_size, raw_size;
    struct result musl, raw;

    musl = call_list(form, path, fd, NULL, 0, 0);
    raw = call_list(form, path, fd, NULL, 0, 1);
    if (musl.value <= 0 || raw.value <= 0 || musl.value > (long)sizeof(musl_list) ||
        raw.value > (long)sizeof(raw_list)) return 0;
    musl_size = musl.value;
    raw_size = raw.value;

    memset(musl_list, 0xa5, sizeof(musl_list));
    memset(raw_list, 0xa5, sizeof(raw_list));
    musl = call_list(form, path, fd, musl_list, sizeof(musl_list), 0);
    raw = call_list(form, path, fd, raw_list, sizeof(raw_list), 1);
    return musl.value == musl_size && raw.value == raw_size &&
           musl_list[musl.value - 1] == '\0' && raw_list[raw.value - 1] == '\0' &&
           list_contains(musl_list, (size_t)musl.value, musl_name) &&
           list_contains(musl_list, (size_t)musl.value, raw_name) &&
           list_contains(raw_list, (size_t)raw.value, musl_name) &&
           list_contains(raw_list, (size_t)raw.value, raw_name);
}

static int xattr_unavailable(int error)
{
    return error == EOPNOTSUPP || error == ENOSYS;
}

int main(void)
{
    static const char path_musl_name[] = "user.crabc-x86-path-musl";
    static const char path_raw_name[] = "user.crabc-x86-path-raw";
    static const char nofollow_musl_name[] = "user.crabc-x86-nofollow-musl";
    static const char nofollow_raw_name[] = "user.crabc-x86-nofollow-raw";
    static const char fd_musl_name[] = "user.crabc-x86-fd-musl";
    static const char fd_raw_name[] = "user.crabc-x86-fd-raw";
    static const char flags_name[] = "user.crabc-x86-flags";
    static const char missing_name[] = "user.crabc-x86-missing";
    static const unsigned char path_musl_value[] = {'p', 'm', '\0', '1'};
    static const unsigned char path_raw_value[] = {'p', 'r', '\0', '2'};
    static const unsigned char nofollow_musl_value[] = {'l', 'm', '\0', '3'};
    static const unsigned char nofollow_raw_value[] = {'l', 'r', '\0', '4'};
    static const unsigned char fd_musl_value[] = {'f', 'm', '\0', '5'};
    static const unsigned char fd_raw_value[] = {'f', 'r', '\0', '6'};
    static const unsigned char replacement_value[] = {'r', 'e', 'p', 'l', '\0', 'a', 'c', 'e', 'd'};
    char template[] = "/tmp/crabc-x86-xattr-XXXXXX";
    char path[512];
    unsigned char short_buffer[1];
    int fd = -1;
    int result = 0;
    int unavailable = 0;
    struct result musl, raw;

    if (mkdtemp(template) == NULL ||
        snprintf(path, sizeof(path), "%s/record", template) >= (int)sizeof(path)) {
        return 10;
    }
    fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) { result = 11; goto cleanup; }

    /* A paired first call records a filesystem-policy unavailable branch too. */
    musl = call_set(XATTR_PATH, path, fd, path_musl_name, path_musl_value,
                    sizeof(path_musl_value), XATTR_CREATE, 0);
    raw = call_set(XATTR_PATH, path, fd, path_raw_name, path_raw_value,
                   sizeof(path_raw_value), XATTR_CREATE, 1);
    if (musl.value != 0 || raw.value != 0) {
        if (musl.value == -1 && raw.value == -1 && musl.error == raw.error &&
            xattr_unavailable(musl.error)) {
            unavailable = 1;
            goto cleanup;
        }
        fprintf(stderr, "initial xattr pair: musl=(%ld,%d) raw=(%ld,%d)\n",
                musl.value, musl.error, raw.value, raw.error);
        result = 12;
        goto cleanup;
    }
    if (call_set(XATTR_NOFOLLOW_PATH, path, fd, nofollow_musl_name,
                 nofollow_musl_value, sizeof(nofollow_musl_value), XATTR_CREATE, 0).value != 0 ||
        call_set(XATTR_NOFOLLOW_PATH, path, fd, nofollow_raw_name,
                 nofollow_raw_value, sizeof(nofollow_raw_value), XATTR_CREATE, 1).value != 0 ||
        call_set(XATTR_DESCRIPTOR, path, fd, fd_musl_name, fd_musl_value,
                 sizeof(fd_musl_value), XATTR_CREATE, 0).value != 0 ||
        call_set(XATTR_DESCRIPTOR, path, fd, fd_raw_name, fd_raw_value,
                 sizeof(fd_raw_value), XATTR_CREATE, 1).value != 0) {
        result = 13;
        goto cleanup;
    }

    if (!verify_get_pair(XATTR_PATH, path, fd, path_musl_name, path_musl_value,
                         sizeof(path_musl_value), path_raw_name, path_raw_value,
                         sizeof(path_raw_value)) ||
        !verify_get_pair(XATTR_NOFOLLOW_PATH, path, fd, nofollow_musl_name,
                         nofollow_musl_value, sizeof(nofollow_musl_value),
                         nofollow_raw_name, nofollow_raw_value, sizeof(nofollow_raw_value)) ||
        !verify_get_pair(XATTR_DESCRIPTOR, path, fd, fd_musl_name, fd_musl_value,
                         sizeof(fd_musl_value), fd_raw_name, fd_raw_value,
                         sizeof(fd_raw_value))) {
        result = 14;
        goto cleanup;
    }

    musl = call_get(XATTR_PATH, path, fd, path_musl_name, short_buffer,
                    sizeof(short_buffer), 0);
    raw = call_get(XATTR_PATH, path, fd, path_raw_name, short_buffer,
                   sizeof(short_buffer), 1);
    if (musl.value != -1 || raw.value != -1 || musl.error != ERANGE || raw.error != ERANGE) {
        result = 15;
        goto cleanup;
    }

    musl = call_set(XATTR_PATH, path, fd, flags_name, "initial", 7, XATTR_CREATE, 0);
    raw = call_set(XATTR_PATH, path, fd, flags_name, "again", 5, XATTR_CREATE, 1);
    if (musl.value != 0 || raw.value != -1 || raw.error != EEXIST) {
        result = 16;
        goto cleanup;
    }
    raw = call_set(XATTR_PATH, path, fd, flags_name, replacement_value,
                   sizeof(replacement_value), XATTR_REPLACE, 1);
    musl = call_set(XATTR_PATH, path, fd, missing_name, "missing", 7, XATTR_REPLACE, 0);
    if (raw.value != 0 || musl.value != -1 || musl.error != ENODATA) {
        result = 17;
        goto cleanup;
    }
    raw = call_set(XATTR_PATH, path, fd, flags_name, "invalid", 7, 0x4U, 1);
    if (raw.value != -1 || raw.error != EINVAL) {
        result = 18;
        goto cleanup;
    }
    memset(short_buffer, 0xa5, sizeof(short_buffer));
    raw = call_get(XATTR_PATH, path, fd, flags_name, short_buffer, sizeof(short_buffer), 1);
    if (raw.value != -1 || raw.error != ERANGE) {
        result = 19;
        goto cleanup;
    }

    if (!verify_list_pair(XATTR_PATH, path, fd, path_musl_name, path_raw_name) ||
        !verify_list_pair(XATTR_NOFOLLOW_PATH, path, fd, nofollow_musl_name,
                          nofollow_raw_name) ||
        !verify_list_pair(XATTR_DESCRIPTOR, path, fd, fd_musl_name, fd_raw_name)) {
        result = 20;
        goto cleanup;
    }
    musl = call_list(XATTR_PATH, path, fd, (char *)short_buffer, sizeof(short_buffer), 0);
    raw = call_list(XATTR_PATH, path, fd, (char *)short_buffer, sizeof(short_buffer), 1);
    if (musl.value != -1 || raw.value != -1 || musl.error != ERANGE || raw.error != ERANGE) {
        result = 21;
        goto cleanup;
    }

    if (call_remove(XATTR_PATH, path, fd, path_musl_name, 1).value != 0 ||
        call_remove(XATTR_PATH, path, fd, path_raw_name, 0).value != 0 ||
        call_remove(XATTR_NOFOLLOW_PATH, path, fd, nofollow_musl_name, 1).value != 0 ||
        call_remove(XATTR_NOFOLLOW_PATH, path, fd, nofollow_raw_name, 0).value != 0 ||
        call_remove(XATTR_DESCRIPTOR, path, fd, fd_musl_name, 1).value != 0 ||
        call_remove(XATTR_DESCRIPTOR, path, fd, fd_raw_name, 0).value != 0 ||
        call_remove(XATTR_PATH, path, fd, flags_name, 1).value != 0) {
        result = 22;
        goto cleanup;
    }
    musl = call_get(XATTR_PATH, path, fd, flags_name, NULL, 0, 0);
    raw = call_remove(XATTR_PATH, path, fd, flags_name, 1);
    if (musl.value != -1 || raw.value != -1 || musl.error != ENODATA || raw.error != ENODATA) {
        result = 23;
        goto cleanup;
    }

cleanup:
    if (fd >= 0) close(fd);
    unlink(path);
    rmdir(template);
    if (result != 0) return result;
    if (unavailable) {
        puts("syscalls=set:188,lset:189,fset:190,get:191,lget:192,fget:193,list:194,llist:195,flist:196,remove:197,lremove:198,fremove:199 xattr=unavailable:EOPNOTSUPP-or-ENOSYS raw=matches-musl cleanup=deterministic c-api-selection=excluded");
        return 0;
    }
    puts("syscalls=set:188,lset:189,fset:190,get:191,lget:192,fget:193,list:194,llist:195,flist:196,remove:197,lremove:198,fremove:199 flags=create:1,replace:2 raw=matches-musl forms=path:nofollow:fd value=binary:size-query:prefix list=nul-separated:size-query errors=EEXIST:ENODATA:EINVAL:ERANGE cleanup=deterministic c-api-selection=excluded");
    return 0;
}
