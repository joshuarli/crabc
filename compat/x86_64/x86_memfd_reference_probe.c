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
    int pipe_fds[2] = {-1, -1};

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
    if (fcntl(sealing_fd, F_ADD_SEALS, F_SEAL_SEAL) != 0 ||
        fcntl(sealing_fd, F_GET_SEALS) != final_seals)
        return 22;
    errno = 0;
    if (!expect_error(fcntl(sealing_fd, F_ADD_SEALS, F_SEAL_WRITE), EPERM) ||
        fcntl(sealing_fd, F_GET_SEALS) != final_seals)
        return 23;

    plain_fd = memfd_create("crabc-x86-memfd-plain", 0);
    if (plain_fd < 0)
        return 24;
    if ((fcntl(plain_fd, F_GETFD) & FD_CLOEXEC) != 0)
        return 25;
    if (fcntl(plain_fd, F_GET_SEALS) != F_SEAL_SEAL)
        return 26;
    errno = 0;
    if (!expect_error(fcntl(plain_fd, F_ADD_SEALS, F_SEAL_GROW), EPERM))
        return 27;

    if (pipe(pipe_fds) != 0)
        return 28;
    errno = 0;
    if (!expect_error(fcntl(pipe_fds[0], F_GET_SEALS), EINVAL))
        return 29;

    closed_fd = sealing_fd;
    if (close(closed_fd) != 0)
        return 30;
    sealing_fd = -1;
    errno = 0;
    if (!expect_error(fcntl(closed_fd, F_GETFD), EBADF))
        return 31;
    if (close(plain_fd) != 0 || close(pipe_fds[0]) != 0 ||
        close(pipe_fds[1]) != 0)
        return 32;

    puts("syscall=319 commands=1033,1034 mfd=1,2,4 seals=1,2,4,8,16 name=proc-label fd=cloexec-owned lifecycle=allow-empty:add-grow-shrink:final-seal plain=seal-seal errors=EINVAL,EPERM");
    return 0;
}
