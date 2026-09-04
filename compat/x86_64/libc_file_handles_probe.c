/* Static x86-64 file-handle ABI fixture.
 *
 * Raw syscalls provide only fixture setup, observation, and cleanup. The
 * candidate owns name_to_handle_at/open_by_handle_at; filesystem support and
 * CAP_DAC_READ_SEARCH are intentionally environmental kernel outcomes.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

enum {
    FIXTURE_AT_FDCWD = -100,
    FIXTURE_EBADF = 9,
    FIXTURE_EFAULT = 14,
    FIXTURE_EINVAL = 22,
    FIXTURE_ENOSYS = 38,
    FIXTURE_EOPNOTSUPP = 95,
    FIXTURE_EOVERFLOW = 75,
    FIXTURE_EPERM = 1,
    FIXTURE_O_DIRECTORY = 0200000,
    FIXTURE_O_CREAT = 0100,
    FIXTURE_O_EXCL = 0200,
    FIXTURE_O_PATH = 010000000,
    FIXTURE_O_RDWR = 02,
    FIXTURE_O_RDONLY = 0,
};

_Static_assert(sizeof(struct file_handle) == 8 &&
                   offsetof(struct file_handle, f_handle) == 8,
               "variable-sized file_handle storage");
_Static_assert(SYS_name_to_handle_at == 303 && SYS_open_by_handle_at == 304,
               "Linux x86-64 file-handle syscall numbers");
_Static_assert(SYS_openat == 257 && SYS_close == 3,
               "Linux x86-64 fixture syscall numbers");

static long raw_syscall1(long number, long argument1)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(argument1)
                     : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
                         long argument3)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(argument1), "S"(argument2),
                       "d"(argument3)
                     : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2,
                         long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(argument1), "S"(argument2),
                       "d"(argument3), "r"(register4)
                     : "rcx", "r11", "memory");
    return result;
}

static int acceptable_unsupported(int error)
{
    return error == FIXTURE_EOPNOTSUPP || error == FIXTURE_ENOSYS ||
           error == FIXTURE_EPERM || error == FIXTURE_EOVERFLOW;
}

int crabc_x86_64_file_handles_probe(void)
{
    static const char path[] = "crabc-file-handle-fixture";
    struct {
        struct file_handle header;
        unsigned char bytes[MAX_HANDLE_SZ];
    } storage;
    int mount_id = 0;
    int mount_fd = -1;
    int result;
    long raw_fd;
    long fixture_fd;
    unsigned int reported_bytes;
    int reported_type;

    fixture_fd = raw_syscall4(SYS_openat, FIXTURE_AT_FDCWD,
                               (long)(uintptr_t)path,
                               FIXTURE_O_CREAT | FIXTURE_O_EXCL | FIXTURE_O_RDWR,
                               0600);
    if (fixture_fd < 0)
        return 1;
    if (raw_syscall1(SYS_close, fixture_fd) != 0)
        return 2;

    __builtin_memset(&storage, 0, sizeof(storage));
    storage.header.handle_bytes = MAX_HANDLE_SZ;
    errno = FIXTURE_EINVAL;
    result = name_to_handle_at(FIXTURE_AT_FDCWD, path, &storage.header,
                               &mount_id, 0);
    if (result < 0) {
        if (!acceptable_unsupported(errno))
            return 3;
        goto pointer_cases;
    }
    if (result != 0 || mount_id <= 0 || storage.header.handle_bytes == 0 ||
        storage.header.handle_bytes > MAX_HANDLE_SZ)
        return 4;
    reported_bytes = storage.header.handle_bytes;
    reported_type = storage.header.handle_type;
    if (reported_type <= 0)
        return 5;

    raw_fd = raw_syscall4(SYS_openat, FIXTURE_AT_FDCWD, (long)(uintptr_t)".",
                          FIXTURE_O_PATH | FIXTURE_O_DIRECTORY, 0);
    if (raw_fd < 0)
        return 6;
    mount_fd = (int)raw_fd;
    errno = FIXTURE_EINVAL;
    result = open_by_handle_at(mount_fd, &storage.header, FIXTURE_O_RDONLY);
    if (result >= 0) {
        (void)raw_syscall1(SYS_close, result);
    } else if (errno != FIXTURE_EPERM && errno != FIXTURE_EBADF &&
               errno != FIXTURE_EFAULT) {
        (void)raw_syscall1(SYS_close, mount_fd);
        return 7;
    }
    (void)raw_syscall1(SYS_close, mount_fd);
    __builtin_memset(&storage, 0, sizeof(storage));
    storage.header.handle_bytes = reported_bytes - 1;
    errno = 0;
    result = name_to_handle_at(FIXTURE_AT_FDCWD, path, &storage.header,
                               &mount_id, 0);
    if (result != -1 || (errno != FIXTURE_EOVERFLOW && errno != FIXTURE_EINVAL &&
                         errno != FIXTURE_EOPNOTSUPP && errno != FIXTURE_EPERM))
        return 8;

pointer_cases:
    errno = 0;
    if (name_to_handle_at(FIXTURE_AT_FDCWD, (const char *)0, &storage.header,
                          &mount_id, 0) != -1 ||
        (errno != FIXTURE_EFAULT && errno != FIXTURE_EOPNOTSUPP &&
         errno != FIXTURE_EPERM))
        return 9;
    errno = 0;
    if (name_to_handle_at(FIXTURE_AT_FDCWD, path, (struct file_handle *)0,
                          &mount_id, 0) != -1 ||
        (errno != FIXTURE_EFAULT && errno != FIXTURE_EOPNOTSUPP &&
         errno != FIXTURE_EPERM))
        return 10;
    errno = 0;
    if (open_by_handle_at(-1, (struct file_handle *)0, FIXTURE_O_RDONLY) != -1 ||
        (errno != FIXTURE_EBADF && errno != FIXTURE_EFAULT &&
         errno != FIXTURE_EPERM))
        return 11;
    return 0;
}

#ifndef CRABC_FILE_HANDLES_FREESTANDING
int main(void)
{
    return crabc_x86_64_file_handles_probe();
}
#endif
