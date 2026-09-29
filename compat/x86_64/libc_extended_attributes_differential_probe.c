/* Operation transcript for the selected static xattr C ABI. The same source
 * runs against pinned musl and the freestanding candidate on one filesystem.
 * Each line records a return value, errno, and the entire caller buffer so
 * successful writes, untouched tails, and error paths remain observable.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/xattr.h>

enum { BUFFER_SIZE = 128, UNTOUCHED = 0xa5, ERRNO_SENTINEL = 90 };

static long raw_syscall6(long number, long a, long b, long c, long d, long e, long f)
{
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return result;
}

static void emit(const char *label, long result, int error,
    const unsigned char *bytes, size_t length)
{
    static const char hex[] = "0123456789abcdef";
    char line[BUFFER_SIZE * 2 + 96];
    char digits[24];
    size_t used = 0, count, index;
    unsigned long magnitude;
    long fields[2] = {result, error};

    while (*label) line[used++] = *label++;
    for (index = 0; index != 2; ++index) {
        long value = fields[index];
        line[used++] = ' ';
        if (value < 0) line[used++] = '-';
        magnitude = value < 0 ? (unsigned long)(-(value + 1)) + 1 : (unsigned long)value;
        count = 0;
        do {
            digits[count++] = (char)('0' + magnitude % 10);
            magnitude /= 10;
        } while (magnitude);
        while (count) line[used++] = digits[--count];
    }
    if (bytes) {
        line[used++] = ' ';
        for (index = 0; index < length; ++index) {
            line[used++] = hex[bytes[index] >> 4];
            line[used++] = hex[bytes[index] & 15];
        }
    }
    line[used++] = '\n';
    (void)raw_syscall6(SYS_write, 1, (long)line, used, 0, 0, 0);
}

static void fill(unsigned char *bytes)
{
    size_t index;
    for (index = 0; index < BUFFER_SIZE; ++index) bytes[index] = UNTOUCHED;
}

enum form { PATH, LINK, FD };

static int set(enum form form, const char *path, int fd, const char *name,
    const void *value, size_t size, int flags)
{
    if (form == PATH) return setxattr(path, name, value, size, flags);
    if (form == LINK) return lsetxattr(path, name, value, size, flags);
    return fsetxattr(fd, name, value, size, flags);
}

static long get(enum form form, const char *path, int fd, const char *name,
    void *value, size_t size)
{
    if (form == PATH) return getxattr(path, name, value, size);
    if (form == LINK) return lgetxattr(path, name, value, size);
    return fgetxattr(fd, name, value, size);
}

static long list(enum form form, const char *path, int fd, void *value, size_t size)
{
    if (form == PATH) return listxattr(path, value, size);
    if (form == LINK) return llistxattr(path, value, size);
    return flistxattr(fd, value, size);
}

static int remove_attribute(enum form form, const char *path, int fd,
    const char *name)
{
    if (form == PATH) return removexattr(path, name);
    if (form == LINK) return lremovexattr(path, name);
    return fremovexattr(fd, name);
}

#define TRACE_STATUS(label, expression) do { \
    long traced_result; \
    errno = ERRNO_SENTINEL; \
    traced_result = (expression); \
    emit(label, traced_result, errno, NULL, 0); \
} while (0)

#define TRACE_BUFFER(label, expression) do { \
    long traced_result; \
    fill(buffer); \
    errno = ERRNO_SENTINEL; \
    traced_result = (expression); \
    emit(label, traced_result, errno, buffer, sizeof(buffer)); \
} while (0)

static int run(void)
{
    static const char file[] = "xattr-differential-file";
    static const char link[] = "xattr-differential-link";
    static const char alpha[] = "user.crabc-diff-alpha";
    static const char beta[] = "user.crabc-diff-beta";
    static const char absent[] = "user.crabc-diff-absent";
    static const unsigned char first[] = {'a', 0, 'b'};
    static const unsigned char second[] = {'c', 0, 'd', 0, 'e', 'f'};
    unsigned char buffer[BUFFER_SIZE];
    long descriptor = raw_syscall6(SYS_openat, AT_FDCWD, (long)file,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600, 0, 0);
    long initial_result;
    int form;
    if (descriptor < 0) return 10;
    errno = ERRNO_SENTINEL;
    initial_result = setxattr(file, alpha, first, sizeof(first), XATTR_CREATE);
    if (initial_result < 0 &&
        (errno == EOPNOTSUPP || errno == ENOSYS)) {
        emit("unavailable", -1, errno, NULL, 0);
        (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
        (void)raw_syscall6(SYS_unlink, (long)file, 0, 0, 0, 0, 0);
        return 77;
    }
    emit("initial-set", initial_result, errno, NULL, 0);
    if (raw_syscall6(SYS_symlinkat, (long)file, AT_FDCWD, (long)link,
            0, 0, 0) < 0) return 11;

    for (form = PATH; form <= FD; ++form) {
        const char *path = form == LINK ? link : file;
        const char *name = form == PATH ? "path" : form == LINK ? "lpath" : "fd";
        TRACE_STATUS(name, set((enum form)form, path, (int)descriptor,
            beta, second, sizeof(second), XATTR_CREATE));
        TRACE_STATUS("size", get((enum form)form, path, (int)descriptor,
            alpha, NULL, 0));
        TRACE_BUFFER("get-short", get((enum form)form, path, (int)descriptor,
            alpha, buffer, 1));
        TRACE_BUFFER("get-exact", get((enum form)form, path, (int)descriptor,
            alpha, buffer, sizeof(first)));
        TRACE_STATUS("list-size", list((enum form)form, path,
            (int)descriptor, NULL, 0));
        TRACE_BUFFER("list-short", list((enum form)form, path,
            (int)descriptor, buffer, 1));
        TRACE_BUFFER("list-full", list((enum form)form, path,
            (int)descriptor, buffer, sizeof(buffer)));
        TRACE_STATUS("replace", set((enum form)form, path, (int)descriptor,
            alpha, second, sizeof(second), XATTR_REPLACE));
        TRACE_STATUS("size-after-replace", get((enum form)form, path,
            (int)descriptor, alpha, NULL, 0));
        TRACE_BUFFER("get-after-replace", get((enum form)form, path,
            (int)descriptor, alpha, buffer, sizeof(buffer)));
        TRACE_STATUS("duplicate", set((enum form)form, path, (int)descriptor,
            alpha, first, sizeof(first), XATTR_CREATE));
        TRACE_STATUS("missing-replace", set((enum form)form, path,
            (int)descriptor, absent, first, sizeof(first), XATTR_REPLACE));
        TRACE_STATUS("bad-flags", set((enum form)form, path,
            (int)descriptor, absent, first, sizeof(first), 4));
        TRACE_STATUS("remove", remove_attribute((enum form)form, path,
            (int)descriptor, beta));
        TRACE_STATUS("remove-again", remove_attribute((enum form)form, path,
            (int)descriptor, beta));
        TRACE_BUFFER("list-after-remove", list((enum form)form, path,
            (int)descriptor, buffer, sizeof(buffer)));
    }

    TRACE_STATUS("follow-link-size", get(PATH, link, (int)descriptor,
        alpha, NULL, 0));
    TRACE_STATUS("nofollow-link-set", set(LINK, link, (int)descriptor,
        alpha, first, sizeof(first), XATTR_CREATE));
    TRACE_STATUS("nofollow-link-size", get(LINK, link, (int)descriptor,
        alpha, NULL, 0));
    TRACE_BUFFER("follow-link-list", list(PATH, link, (int)descriptor,
        buffer, sizeof(buffer)));
    TRACE_BUFFER("nofollow-link-list", list(LINK, link, (int)descriptor,
        buffer, sizeof(buffer)));
    TRACE_STATUS("nofollow-link-remove", remove_attribute(LINK, link,
        (int)descriptor, alpha));
    (void)raw_syscall6(SYS_unlink, (long)file, 0, 0, 0, 0, 0);
    TRACE_STATUS("path-after-unlink", get(PATH, file, (int)descriptor,
        alpha, NULL, 0));
    TRACE_STATUS("link-after-unlink", get(PATH, link, (int)descriptor,
        alpha, NULL, 0));
    TRACE_STATUS("fd-after-unlink", get(FD, file, (int)descriptor,
        alpha, NULL, 0));
    TRACE_STATUS("fd-remove-after-unlink", remove_attribute(FD, file,
        (int)descriptor, alpha));
    TRACE_STATUS("fd-missing-after-unlink", get(FD, file, (int)descriptor,
        alpha, NULL, 0));
    (void)raw_syscall6(SYS_unlink, (long)link, 0, 0, 0, 0, 0);
    (void)raw_syscall6(SYS_close, descriptor, 0, 0, 0, 0, 0);
    return 0;
}

#ifdef CRABC_EXTENDED_ATTRIBUTES_FREESTANDING
int crabc_x86_64_extended_attributes_probe(void) { return run(); }
#else
int main(void) { return run(); }
#endif
