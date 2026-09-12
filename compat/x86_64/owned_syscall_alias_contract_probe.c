/*
 * Ordinary successful calls for musl 1.2.6's syscall-facing weak aliases.
 *
 * This intentionally uses one runner-provided regular path so the static
 * oracle and chrooted shared products do not depend on a host /dev layout.
 * The alias reader owns exact address and binding proof; this source owns the
 * normal C-call behavior through every public spelling.
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

#define PAGE_BYTES 4096U

#define CHECK(expression) do { if (!(expression)) return __LINE__; } while (0)

int main(int argc, char **argv)
{
    struct timespec now;
    struct timespec immediate = { 0, 0 };
    struct stat metadata;
    struct statfs filesystem;
    struct sysinfo information;
    struct sigaction action;
    void *mapping;
    int descriptor;
    int duplicate;

    CHECK(argc == 2);
    CHECK(clock_gettime(CLOCK_REALTIME, &now) == 0);
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, 0, &immediate, NULL) == 0);

    descriptor = open(argv[1], O_RDONLY);
    CHECK(descriptor >= 0);
    CHECK(fstat(descriptor, &metadata) == 0);
    CHECK(fstatat(AT_FDCWD, argv[1], &metadata, 0) == 0);
    CHECK(fstatfs(descriptor, &filesystem) == 0);
    CHECK(statfs(argv[1], &filesystem) == 0);
    CHECK(lseek(descriptor, 0, SEEK_CUR) >= 0);
    duplicate = dup3(descriptor, descriptor + 32, O_CLOEXEC);
    CHECK(duplicate >= 0);
    CHECK(close(duplicate) == 0);
    CHECK(close(descriptor) == 0);

    mapping = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    CHECK(mprotect(mapping, PAGE_BYTES, PROT_READ | PROT_WRITE) == 0);
    CHECK(madvise(mapping, PAGE_BYTES, MADV_NORMAL) == 0);
    CHECK(munmap(mapping, PAGE_BYTES) == 0);

    CHECK(sysinfo(&information) == 0);
    CHECK(sigaction(SIGUSR1, NULL, &action) == 0);
    CHECK(write(STDOUT_FILENO, "owned-syscall-alias-contract-ok\n", 32) == 32);
    return 0;
}
