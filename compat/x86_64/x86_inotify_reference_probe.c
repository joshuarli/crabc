/*
 * Pinned-musl/raw Linux/x86-64 inotify ABI and behavior reference.
 *
 * `sys/inotify.h` calls below are a pinned-musl oracle for the private Rust
 * descriptor boundary. The raw calls independently pin Linux's x86-64
 * syscall ABI. This fixture selects no crabc C inotify API, errno/TLS
 * contract, installed header, or public x86 support.
 */
#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8, "x86 LP64 widths");
_Static_assert(sizeof(struct inotify_event) == 16,
               "x86 inotify event header size");
_Static_assert(_Alignof(struct inotify_event) == 4,
               "x86 inotify event header alignment");
_Static_assert(offsetof(struct inotify_event, wd) == 0 &&
                   offsetof(struct inotify_event, mask) == 4 &&
                   offsetof(struct inotify_event, cookie) == 8 &&
                   offsetof(struct inotify_event, len) == 12 &&
                   offsetof(struct inotify_event, name) == 16,
               "x86 inotify event header offsets");
_Static_assert(SYS_inotify_init1 == 294, "x86 inotify_init1 syscall number");
_Static_assert(SYS_inotify_add_watch == 254,
               "x86 inotify_add_watch syscall number");
_Static_assert(SYS_inotify_rm_watch == 255,
               "x86 inotify_rm_watch syscall number");
_Static_assert(IN_NONBLOCK == 0x00000800 && IN_CLOEXEC == 0x00080000,
               "x86 inotify creation flags");
_Static_assert(IN_CREATE == 0x00000100 && IN_IGNORED == 0x00008000,
               "x86 selected inotify event bits");

enum {
    EVENT_BUFFER_SIZE = 4096,
    WAIT_MILLISECONDS = 1000,
};

struct call_result {
    long value;
    int error;
};

static struct call_result call_init1(int raw, int flags)
{
    struct call_result result;

    errno = 0;
    result.value = raw ? syscall(SYS_inotify_init1, flags) : inotify_init1(flags);
    result.error = errno;
    return result;
}

static struct call_result call_add_watch(int raw, int fd, const char *path,
                                         uint32_t mask)
{
    struct call_result result;

    errno = 0;
    result.value = raw ? syscall(SYS_inotify_add_watch, fd, path, mask)
                       : inotify_add_watch(fd, path, mask);
    result.error = errno;
    return result;
}

static struct call_result call_rm_watch(int raw, int fd, int watch)
{
    struct call_result result;

    errno = 0;
    result.value = raw ? syscall(SYS_inotify_rm_watch, fd, watch)
                       : inotify_rm_watch(fd, watch);
    result.error = errno;
    return result;
}

static int is_error(struct call_result result, int error)
{
    return result.value == -1 && result.error == error;
}

static int has_requested_descriptor_flags(int fd)
{
    int descriptor_flags = fcntl(fd, F_GETFD);
    int status_flags = fcntl(fd, F_GETFL);

    return descriptor_flags >= 0 && status_flags >= 0 &&
           (descriptor_flags & FD_CLOEXEC) != 0 &&
           (status_flags & O_NONBLOCK) != 0;
}

static int initially_would_block(int fd)
{
    unsigned char bytes[sizeof(struct inotify_event)];
    ssize_t result;

    errno = 0;
    result = read(fd, bytes, sizeof(bytes));
    return result == -1 && errno == EAGAIN;
}

static int wait_readable(int fd)
{
    struct pollfd pollfd = {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };
    int result;

    do {
        result = poll(&pollfd, 1, WAIT_MILLISECONDS);
    } while (result == -1 && errno == EINTR);
    return result == 1 && (pollfd.revents & POLLIN) != 0;
}

/*
 * Linux makes each complete event 4-byte aligned and includes its trailing
 * NUL/padding in `len`. Parse byte-wise rather than assuming the caller's
 * read buffer has a record alignment stronger than the kernel contract.
 */
static int contains_named_event(const unsigned char *bytes, size_t length,
                                int expected_watch, uint32_t required_mask,
                                const unsigned char *expected_name,
                                size_t expected_name_length)
{
    size_t offset = 0;

    while (offset < length) {
        struct inotify_event header;
        const unsigned char *name;
        const unsigned char *terminator;
        size_t record_length;

        if (length - offset < sizeof(header)) return 0;
        memcpy(&header, bytes + offset, sizeof(header));
        if (header.len > length - offset - sizeof(header)) return 0;
        record_length = sizeof(header) + header.len;
        name = bytes + offset + sizeof(header);
        terminator = memchr(name, '\0', header.len);
        if (terminator == NULL) return 0;
        if (header.wd == expected_watch &&
            (header.mask & required_mask) == required_mask &&
            (size_t)(terminator - name) == expected_name_length &&
            memcmp(name, expected_name, expected_name_length) == 0) {
            return 1;
        }
        offset += record_length;
    }
    return 0;
}

static int contains_ignored_event(const unsigned char *bytes, size_t length,
                                  int expected_watch)
{
    size_t offset = 0;

    while (offset < length) {
        struct inotify_event header;
        size_t record_length;

        if (length - offset < sizeof(header)) return 0;
        memcpy(&header, bytes + offset, sizeof(header));
        if (header.len > length - offset - sizeof(header)) return 0;
        record_length = sizeof(header) + header.len;
        if (header.wd == expected_watch && (header.mask & IN_IGNORED) != 0 &&
            header.len == 0) {
            return 1;
        }
        offset += record_length;
    }
    return 0;
}

static int read_named_create(int fd, int watch, const unsigned char *name,
                             size_t name_length)
{
    unsigned char bytes[EVENT_BUFFER_SIZE];
    ssize_t length;

    if (!wait_readable(fd)) return 0;
    length = read(fd, bytes, sizeof(bytes));
    return length > 0 &&
           contains_named_event(bytes, (size_t)length, watch, IN_CREATE, name,
                                name_length);
}

static int read_ignored(int fd, int watch)
{
    unsigned char bytes[EVENT_BUFFER_SIZE];
    ssize_t length;

    if (!wait_readable(fd)) return 0;
    length = read(fd, bytes, sizeof(bytes));
    return length > 0 && contains_ignored_event(bytes, (size_t)length, watch);
}

int main(void)
{
    static const unsigned char created_name[] = {
        'c', 'r', 'e', 'a', 't', 'e', 'd', '-', 0xff, '\0',
    };
    char template[] = "/tmp/crabc-x86-inotify-XXXXXX";
    char missing_path[sizeof(template) + sizeof("/missing")];
    char overlong_component[257];
    char *root;
    struct call_result result;
    int root_fd = -1;
    int file_fd = -1;
    int musl_fd = -1;
    int raw_fd = -1;
    int musl_watch = -1;
    int raw_watch = -1;
    int missing_length;
    int status = 0;

    root = mkdtemp(template);
    if (root == NULL) return 2;
    root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) {
        status = 3;
        goto cleanup;
    }
    missing_length = snprintf(missing_path, sizeof(missing_path), "%s/missing", root);
    if (missing_length < 0 || (size_t)missing_length >= sizeof(missing_path)) {
        status = 4;
        goto cleanup;
    }
    memset(overlong_component, 'x', sizeof(overlong_component) - 1);
    overlong_component[sizeof(overlong_component) - 1] = '\0';

    result = call_init1(0, IN_NONBLOCK | IN_CLOEXEC);
    if (result.value < 0) {
        status = 5;
        goto cleanup;
    }
    musl_fd = (int)result.value;
    result = call_init1(1, IN_NONBLOCK | IN_CLOEXEC);
    if (result.value < 0) {
        status = 6;
        goto cleanup;
    }
    raw_fd = (int)result.value;
    if (!has_requested_descriptor_flags(musl_fd) ||
        !has_requested_descriptor_flags(raw_fd) || !initially_would_block(musl_fd) ||
        !initially_would_block(raw_fd)) {
        status = 7;
        goto cleanup;
    }

    if (!is_error(call_init1(0, 1), EINVAL) ||
        !is_error(call_init1(1, 1), EINVAL)) {
        status = 8;
        goto cleanup;
    }

    result = call_add_watch(0, musl_fd, root, IN_CREATE);
    if (result.value < 0) {
        status = 9;
        goto cleanup;
    }
    musl_watch = (int)result.value;
    result = call_add_watch(1, raw_fd, root, IN_CREATE);
    if (result.value < 0) {
        status = 10;
        goto cleanup;
    }
    raw_watch = (int)result.value;

    if (!is_error(call_add_watch(0, musl_fd, missing_path, IN_CREATE), ENOENT) ||
        !is_error(call_add_watch(1, raw_fd, missing_path, IN_CREATE), ENOENT) ||
        !is_error(call_add_watch(0, musl_fd, overlong_component, IN_CREATE),
                  ENAMETOOLONG) ||
        !is_error(call_add_watch(1, raw_fd, overlong_component, IN_CREATE),
                  ENAMETOOLONG) ||
        !is_error(call_add_watch(0, -1, root, IN_CREATE), EBADF) ||
        !is_error(call_add_watch(1, -1, root, IN_CREATE), EBADF)) {
        status = 11;
        goto cleanup;
    }

    file_fd = openat(root_fd, (const char *)created_name,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (file_fd < 0 || close(file_fd) != 0) {
        file_fd = -1;
        status = 12;
        goto cleanup;
    }
    file_fd = -1;
    if (!read_named_create(musl_fd, musl_watch, created_name,
                           sizeof(created_name) - 1) ||
        !read_named_create(raw_fd, raw_watch, created_name,
                           sizeof(created_name) - 1)) {
        status = 13;
        goto cleanup;
    }

    if (call_rm_watch(0, musl_fd, musl_watch).value != 0 ||
        call_rm_watch(1, raw_fd, raw_watch).value != 0 ||
        !read_ignored(musl_fd, musl_watch) || !read_ignored(raw_fd, raw_watch)) {
        status = 14;
        goto cleanup;
    }
    if (!is_error(call_rm_watch(0, musl_fd, musl_watch), EINVAL) ||
        !is_error(call_rm_watch(1, raw_fd, raw_watch), EINVAL) ||
        !is_error(call_rm_watch(0, -1, 0), EBADF) ||
        !is_error(call_rm_watch(1, -1, 0), EBADF)) {
        status = 15;
        goto cleanup;
    }

cleanup:
    if (file_fd >= 0 && close(file_fd) != 0 && status == 0) status = 16;
    if (root_fd >= 0 && unlinkat(root_fd, (const char *)created_name, 0) != 0 &&
        status == 0) {
        status = 17;
    }
    if (raw_fd >= 0 && close(raw_fd) != 0 && status == 0) status = 18;
    if (musl_fd >= 0 && close(musl_fd) != 0 && status == 0) status = 19;
    if (root_fd >= 0 && close(root_fd) != 0 && status == 0) status = 20;
    if (rmdir(template) != 0 && status == 0) status = 21;
    if (status != 0) return status;

    puts("syscalls=inotify_init1:294,inotify_add_watch:254,inotify_rm_watch:255 layout=size16:align4:wd0:mask4:cookie8:len12:name16 flags=nonblock:0x800:cloexec:0x80000 musl=nonblock:cloexec:create-byte-name:remove-ignored raw=matches-musl errors=invalid-flags:EINVAL:missing-path:ENOENT:overlong-path:ENAMETOOLONG:bad-fd:EBADF:bad-watch:EINVAL c-api-selection=excluded");
    return 0;
}
