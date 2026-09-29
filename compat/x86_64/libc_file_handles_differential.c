/* Compare the two C entries on the same mount and persistent fixture inode.
 * Raw syscalls only create, remove, and close fixture objects or emit records.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "native Linux x86-64 is required"
#endif

#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/syscall.h>

enum { SENTINEL_ERRNO = 777 };

struct observation {
    int32_t case_id;
    int32_t result;
    int32_t error;
    int32_t handle_bytes;
    int32_t handle_type;
    int32_t mount_id;
    uint32_t handle_fingerprint;
};

_Static_assert(sizeof(struct observation) == 28, "fixed differential record");

struct handle_storage {
    struct file_handle header;
    unsigned char bytes[MAX_HANDLE_SZ];
};

static long raw_syscall1(long number, long first)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(first)
                     : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long first, long second, long third)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(first), "S"(second), "d"(third)
                     : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long first, long second, long third,
                         long fourth)
{
    long result;
    register long word4 __asm__("r10") = fourth;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(first), "S"(second), "d"(third),
                       "r"(word4)
                     : "rcx", "r11", "memory");
    return result;
}

static int emit(int id, int result, int error, const struct handle_storage *storage,
                int mount_id)
{
    uint32_t fingerprint = 0;
    unsigned int index;
    if (result == 0 && storage->header.handle_bytes > 0 &&
        storage->header.handle_bytes <= MAX_HANDLE_SZ) {
        fingerprint = 2166136261u;
        for (index = 0; index < storage->header.handle_bytes; ++index)
            fingerprint = (fingerprint ^ storage->bytes[index]) * 16777619u;
    }
    struct observation row = { id, result, error,
                               (int32_t)storage->header.handle_bytes,
                               storage->header.handle_type, mount_id,
                               fingerprint };
    return raw_syscall3(SYS_write, 1, (long)(uintptr_t)&row, sizeof(row)) ==
           (long)sizeof(row) ? 0 : -1;
}

static void reset(struct handle_storage *storage, int capacity)
{
    __builtin_memset(storage, 0, sizeof(*storage));
    storage->header.handle_bytes = (unsigned int)capacity;
}

static int observe_name(int id, int dirfd, const char *path,
                        struct handle_storage *storage, int *mount_id,
                        int flags)
{
    int result;
    int error;
    errno = SENTINEL_ERRNO;
    result = name_to_handle_at(dirfd, path, &storage->header, mount_id, flags);
    error = errno;
    return emit(id, result, error, storage, *mount_id);
}

static int observe_open(int id, int mount_fd, struct handle_storage *storage,
                        int flags)
{
    int result;
    int error;
    errno = SENTINEL_ERRNO;
    result = open_by_handle_at(mount_fd, &storage->header, flags);
    error = errno;
    if (result >= 0) {
        if (raw_syscall1(SYS_close, result) != 0)
            return -1;
        result = 0;
    }
    return emit(id, result, error, storage, -1);
}

int crabc_x86_64_file_handles_probe(void)
{
    static const char path[] = "crabc-file-handle-differential";
    static const char transient[] = "crabc-file-handle-transient";
    static const char symlink_path[] = "crabc-file-handle-symlink";
    struct handle_storage storage;
    struct handle_storage valid;
    int mount_id;
    int full_result;
    int required;
    long file_fd;
    long mount_fd;
    long transient_fd;

    file_fd = raw_syscall4(SYS_openat, AT_FDCWD, (long)(uintptr_t)path,
                           O_CREAT | O_RDWR, 0600);
    mount_fd = raw_syscall4(SYS_openat, AT_FDCWD, (long)(uintptr_t)".",
                            O_PATH | O_DIRECTORY, 0);
    if (file_fd < 0 || mount_fd < 0)
        return 1;

    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ);
    errno = SENTINEL_ERRNO;
    full_result = name_to_handle_at(AT_FDCWD, path, &storage.header, &mount_id, 0);
    if (emit(1, full_result, errno, &storage, mount_id))
        return 2;
    valid = storage;
    required = (int)storage.header.handle_bytes;
    if (full_result == 0 && (mount_id <= 0 || required <= 0 ||
                             required > MAX_HANDLE_SZ || storage.header.handle_type <= 0))
        return 3;

    mount_id = -123;
    reset(&storage, 0);
    if (observe_name(2, AT_FDCWD, path, &storage, &mount_id, 0)) return 4;
    if (full_result == 0 &&
        (errno != EOVERFLOW || (int)storage.header.handle_bytes != required))
        return 5;

    mount_id = -123;
    reset(&storage, 1);
    if (observe_name(3, AT_FDCWD, path, &storage, &mount_id, 0)) return 6;
    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ + 1);
    if (observe_name(4, AT_FDCWD, path, &storage, &mount_id, 0)) return 7;
    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ);
    if (observe_name(5, AT_FDCWD, path, &storage, &mount_id, 0x40000000)) return 8;
    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ);
    if (observe_name(6, -1, path, &storage, &mount_id, 0)) return 9;
    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ);
    if (observe_name(7, (int)file_fd, "", &storage, &mount_id, AT_EMPTY_PATH)) return 10;
    if (raw_syscall1(SYS_close, file_fd) != 0) return 11;
    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ);
    if (observe_name(8, (int)file_fd, "", &storage, &mount_id, AT_EMPTY_PATH)) return 12;
    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ);
    if (observe_name(9, AT_FDCWD, (const char *)0, &storage, &mount_id, 0)) return 13;

    if (full_result == 0)
        storage = valid;
    else
        reset(&storage, 0);
    if (observe_open(10, (int)mount_fd, &storage, O_RDONLY)) return 14;
    if (observe_open(11, -1, &storage, O_RDONLY)) return 15;
    if (observe_open(12, (int)mount_fd, &storage, 0x40000000)) return 16;
    reset(&storage, MAX_HANDLE_SZ + 1);
    if (observe_open(13, (int)mount_fd, &storage, O_RDONLY)) return 17;
    if (raw_syscall1(SYS_close, mount_fd) != 0) return 18;
    if (observe_open(14, (int)mount_fd, &storage, O_RDONLY)) return 19;

    transient_fd = raw_syscall4(SYS_openat, AT_FDCWD,
                                (long)(uintptr_t)transient,
                                O_CREAT | O_RDWR, 0600);
    if (transient_fd < 0) return 20;
    if (raw_syscall1(SYS_close, transient_fd) != 0) return 21;
    if (raw_syscall3(SYS_unlinkat, AT_FDCWD, (long)(uintptr_t)transient, 0) != 0)
        return 22;
    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ);
    if (observe_name(15, AT_FDCWD, transient, &storage, &mount_id, 0)) return 23;
    {
        long symlink_result = raw_syscall3(SYS_symlinkat, (long)(uintptr_t)path,
                                           AT_FDCWD, (long)(uintptr_t)symlink_path);
        if (symlink_result != 0 && symlink_result != -EEXIST)
            return 24;
    }
    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ);
    if (observe_name(16, AT_FDCWD, symlink_path, &storage, &mount_id, 0)) return 25;
    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ);
    if (observe_name(17, AT_FDCWD, symlink_path, &storage, &mount_id,
                     AT_SYMLINK_FOLLOW)) return 26;
    mount_id = -123;
    reset(&storage, MAX_HANDLE_SZ);
    errno = SENTINEL_ERRNO;
    {
        int result = name_to_handle_at(AT_FDCWD, path, 0, &mount_id, 0);
        if (emit(18, result, errno, &storage, mount_id)) return 28;
    }
    reset(&storage, 0);
    errno = SENTINEL_ERRNO;
    {
        int result = open_by_handle_at(-1, 0, O_RDONLY);
        if (emit(19, result, errno, &storage, -1)) return 29;
    }
    return 0;
}

#ifndef CRABC_FILE_HANDLES_FREESTANDING
int main(void)
{
    return crabc_x86_64_file_handles_probe();
}
#endif
