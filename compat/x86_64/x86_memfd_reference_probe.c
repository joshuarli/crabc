/* Pinned-musl Linux/x86-64 memfd and sealing ABI/behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(SYS_memfd_create == 319, "x86 memfd_create syscall number");
_Static_assert(SYS_fcntl == 72, "x86 fcntl syscall number");
_Static_assert(MFD_CLOEXEC == 0x0001U, "x86 MFD_CLOEXEC");
_Static_assert(MFD_ALLOW_SEALING == 0x0002U, "x86 MFD_ALLOW_SEALING");
_Static_assert(MFD_HUGETLB == 0x0004U, "x86 MFD_HUGETLB");
_Static_assert(F_ADD_SEALS == 1033, "x86 F_ADD_SEALS command");
_Static_assert(F_GET_SEALS == 1034, "x86 F_GET_SEALS command");
_Static_assert(F_SEAL_SEAL == 0x0001, "x86 F_SEAL_SEAL");
_Static_assert(F_SEAL_SHRINK == 0x0002, "x86 F_SEAL_SHRINK");
_Static_assert(F_SEAL_GROW == 0x0004, "x86 F_SEAL_GROW");
_Static_assert(F_SEAL_WRITE == 0x0008, "x86 F_SEAL_WRITE");
_Static_assert(F_SEAL_FUTURE_WRITE == 0x0010, "x86 F_SEAL_FUTURE_WRITE");

static int expect_error(int result, int error)
{
    return result == -1 && errno == error;
}

static int named_memfd_target(int fd)
{
    static const char expected[] =
        "/memfd:crabc-x86-memfd-reference (deleted)";
    char proc_path[64];
    char target[sizeof(expected)];
    int proc_path_length;
    ssize_t target_length;

    proc_path_length = snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    if (proc_path_length < 0 || (size_t)proc_path_length >= sizeof(proc_path))
        return 0;
    target_length = readlink(proc_path, target, sizeof(target));
    return target_length == (ssize_t)(sizeof(expected) - 1) &&
        memcmp(target, expected, sizeof(expected) - 1) == 0;
}

int main(void)
{
    static const char name[] = "crabc-x86-memfd-reference";
    static const char payload[] = "memfd";
    char boundary_name[251];
    char received[sizeof(payload) - 1];
    const int added_seals = F_SEAL_SHRINK | F_SEAL_GROW;
    const int final_seals = added_seals | F_SEAL_SEAL;
    int boundary_fd;
    int closed_fd;
    int sealing_fd = -1;
    int plain_fd = -1;
    int raw_fd = -1;
    int write_fd = -1;
    int future_write_fd = -1;
    int pipe_fds[2] = {-1, -1};
    unsigned char future_byte;
    void *write_mapping = MAP_FAILED;
    void *future_mapping = MAP_FAILED;
    void *new_mapping;

    /* Linux 5.10 accepts 249 content bytes; the limit excludes the NUL. */
    memset(boundary_name, 'x', sizeof(boundary_name) - 1);
    boundary_name[sizeof(boundary_name) - 2] = '\0';

    errno = 0;
    if (!expect_error(memfd_create(name, UINT_MAX), EINVAL))
        return 10;
    boundary_fd = memfd_create(boundary_name, 0);
    if (boundary_fd < 0)
        return 11;
    if (close(boundary_fd) != 0)
        return 12;
    boundary_name[sizeof(boundary_name) - 2] = 'x';
    boundary_name[sizeof(boundary_name) - 1] = '\0';
    errno = 0;
    if (!expect_error(memfd_create(boundary_name, 0), EINVAL))
        return 13;

    /* Pin the raw three-register fcntl boundary separately from musl's C API. */
    raw_fd = memfd_create("crabc-x86-memfd-raw-fcntl", MFD_ALLOW_SEALING);
    if (raw_fd < 0)
        return 100;
    if (syscall(SYS_fcntl, raw_fd, F_GET_SEALS) != 0)
        return 101;
    if (syscall(SYS_fcntl, raw_fd, F_ADD_SEALS, F_SEAL_SHRINK) != 0 ||
        syscall(SYS_fcntl, raw_fd, F_GET_SEALS) != F_SEAL_SHRINK)
        return 102;
    errno = 0;
    if (!expect_error(
            syscall(SYS_fcntl, raw_fd, F_ADD_SEALS, 0x40000000U), EINVAL
        ) || syscall(SYS_fcntl, raw_fd, F_GET_SEALS) != F_SEAL_SHRINK)
        return 103;
    if (close(raw_fd) != 0)
        return 104;
    raw_fd = -1;

    sealing_fd = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (sealing_fd < 0)
        return 14;
    if ((fcntl(sealing_fd, F_GETFD) & FD_CLOEXEC) == 0)
        return 15;
    if (!named_memfd_target(sealing_fd))
        return 16;

    if (write(sealing_fd, payload, sizeof(payload) - 1) !=
        (ssize_t)(sizeof(payload) - 1))
        return 17;
    if (lseek(sealing_fd, 0, SEEK_SET) != 0)
        return 18;
    if (read(sealing_fd, received, sizeof(received)) !=
            (ssize_t)sizeof(received) ||
        memcmp(received, payload, sizeof(received)) != 0)
        return 19;

    if (fcntl(sealing_fd, F_GET_SEALS) != 0)
        return 20;
    if (fcntl(sealing_fd, F_ADD_SEALS, added_seals) != 0 ||
        fcntl(sealing_fd, F_GET_SEALS) != added_seals)
        return 21;
    errno = 0;
    if (!expect_error(ftruncate(sealing_fd, sizeof(payload)), EPERM))
        return 22;
    errno = 0;
    if (!expect_error(ftruncate(sealing_fd, sizeof(payload) - 2), EPERM) ||
        fcntl(sealing_fd, F_GET_SEALS) != added_seals)
        return 23;
    if (fcntl(sealing_fd, F_ADD_SEALS, F_SEAL_SEAL) != 0 ||
        fcntl(sealing_fd, F_GET_SEALS) != final_seals)
        return 24;
    errno = 0;
    if (!expect_error(fcntl(sealing_fd, F_ADD_SEALS, F_SEAL_WRITE), EPERM) ||
        fcntl(sealing_fd, F_GET_SEALS) != final_seals)
        return 25;

    write_fd = memfd_create("crabc-x86-memfd-write", MFD_ALLOW_SEALING);
    if (write_fd < 0)
        return 26;
    if (write(write_fd, payload, sizeof(payload) - 1) !=
        (ssize_t)(sizeof(payload) - 1))
        return 27;
    if (ftruncate(write_fd, 4096) != 0)
        return 105;
    write_mapping = mmap(
        NULL,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        write_fd,
        0
    );
    if (write_mapping == MAP_FAILED)
        return 106;
    errno = 0;
    if (!expect_error(fcntl(write_fd, F_ADD_SEALS, F_SEAL_WRITE), EBUSY) ||
        fcntl(write_fd, F_GET_SEALS) != 0)
        return 107;
    if (munmap(write_mapping, 4096) != 0)
        return 108;
    write_mapping = MAP_FAILED;
    if (fcntl(write_fd, F_ADD_SEALS, F_SEAL_WRITE) != 0 ||
        fcntl(write_fd, F_GET_SEALS) != F_SEAL_WRITE)
        return 28;
    errno = 0;
    if (!expect_error(pwrite(write_fd, "!", 1, 0), EPERM))
        return 29;

    future_write_fd = memfd_create(
        "crabc-x86-memfd-future-write", MFD_ALLOW_SEALING
    );
    if (future_write_fd < 0)
        return 30;
    if (ftruncate(future_write_fd, 4096) != 0)
        return 31;
    future_mapping = mmap(
        NULL,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        future_write_fd,
        0
    );
    if (future_mapping == MAP_FAILED)
        return 32;
    ((unsigned char *)future_mapping)[0] = 'a';
    if (fcntl(future_write_fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) != 0 ||
        fcntl(future_write_fd, F_GET_SEALS) != F_SEAL_FUTURE_WRITE)
        return 33;
    ((unsigned char *)future_mapping)[0] = 'b';
    if (pread(future_write_fd, &future_byte, 1, 0) != 1 || future_byte != 'b')
        return 34;
    errno = 0;
    if (!expect_error(pwrite(future_write_fd, "!", 1, 0), EPERM))
        return 35;
    errno = 0;
    new_mapping = mmap(
        NULL,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        future_write_fd,
        0
    );
    if (new_mapping != MAP_FAILED) {
        (void)munmap(new_mapping, 4096);
        return 36;
    }
    if (errno != EPERM)
        return 37;
    if (munmap(future_mapping, 4096) != 0)
        return 38;
    future_mapping = MAP_FAILED;

    plain_fd = memfd_create("crabc-x86-memfd-plain", 0);
    if (plain_fd < 0)
        return 39;
    if ((fcntl(plain_fd, F_GETFD) & FD_CLOEXEC) != 0)
        return 40;
    if (fcntl(plain_fd, F_GET_SEALS) != F_SEAL_SEAL)
        return 41;
    errno = 0;
    if (!expect_error(fcntl(plain_fd, F_ADD_SEALS, F_SEAL_GROW), EPERM))
        return 42;

    if (pipe(pipe_fds) != 0)
        return 43;
    errno = 0;
    if (!expect_error(fcntl(pipe_fds[0], F_GET_SEALS), EINVAL))
        return 44;
    errno = 0;
    if (!expect_error(fcntl(pipe_fds[0], F_ADD_SEALS, F_SEAL_GROW), EPERM))
        return 45;
    errno = 0;
    if (!expect_error(fcntl(pipe_fds[1], F_ADD_SEALS, F_SEAL_GROW), EINVAL))
        return 46;

    closed_fd = sealing_fd;
    if (close(closed_fd) != 0)
        return 47;
    sealing_fd = -1;
    errno = 0;
    if (!expect_error(fcntl(closed_fd, F_GETFD), EBADF))
        return 48;
    errno = 0;
    if (!expect_error(fcntl(closed_fd, F_GET_SEALS), EBADF))
        return 49;
    errno = 0;
    if (!expect_error(fcntl(closed_fd, F_ADD_SEALS, F_SEAL_GROW), EBADF))
        return 51;
    if (close(write_fd) != 0 || close(future_write_fd) != 0 ||
        close(plain_fd) != 0 || close(pipe_fds[0]) != 0 ||
        close(pipe_fds[1]) != 0)
        return 50;

    puts("syscalls=319,72 commands=1033,1034 mfd=1,2,4 seals=1,2,4,8,16 name=249-ok:250-einval:proc-label fd=cloexec-owned lifecycle=allow-empty:write-live-map-ebusy:grow-shrink-enforced:write-enforced:future-write-existing-map-preserved:direct-write-rejected:new-writable-map-rejected:final-seal plain=seal-seal errors=EINVAL,EPERM,EBUSY,EBADF");
    return 0;
}
