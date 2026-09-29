/* Pinned-musl Linux/x86-64 lseek/fsync/fdatasync ABI and behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(SYS_lseek == 8, "x86 lseek syscall number");
_Static_assert(SYS_fsync == 74, "x86 fsync syscall number");
_Static_assert(SYS_fdatasync == 75, "x86 fdatasync syscall number");
_Static_assert(sizeof(off_t) == sizeof(int64_t), "x86 signed 64-bit off_t");
_Static_assert((off_t)-1 < (off_t)0, "x86 off_t is signed");
_Static_assert(SEEK_SET == 0, "x86 SEEK_SET value");
_Static_assert(SEEK_CUR == 1, "x86 SEEK_CUR value");
_Static_assert(SEEK_END == 2, "x86 SEEK_END value");
_Static_assert(SEEK_DATA == 3, "x86 SEEK_DATA value");
_Static_assert(SEEK_HOLE == 4, "x86 SEEK_HOLE value");

static int expect_error(long result, int error)
{
    return result == -1 && errno == error;
}

struct interrupt_state {
    int descriptor, writer, number, tid;
    atomic_int returned, observed;
};
static volatile sig_atomic_t io_signal_seen;
static void io_signal_handler(int signal_number)
{
    (void)signal_number;
    io_signal_seen = 1;
}
static int before_deadline(const struct timespec *deadline)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return now.tv_sec < deadline->tv_sec ||
        (now.tv_sec == deadline->tv_sec && now.tv_nsec < deadline->tv_nsec);
}
static void *interrupt_observer(void *context)
{
    struct interrupt_state *state = context;
    char path[96];
    struct timespec deadline, pause = {0, 1000000};
    if (clock_gettime(CLOCK_MONOTONIC, &deadline)) goto failed;
    deadline.tv_sec += 5;
    snprintf(path, sizeof path, "/proc/self/task/%d/syscall", state->tid);
    while (before_deadline(&deadline)) {
        FILE *record = fopen(path, "r");
        if (!record) goto failed;
        long number = -1; unsigned long descriptor = 0;
        int parsed = fscanf(record, "%ld %lx", &number, &descriptor);
        fclose(record);
        if (parsed == 2 && number == state->number && descriptor == (unsigned long)state->descriptor) {
            if (syscall(SYS_tgkill, getpid(), state->tid, SIGUSR1)) goto failed;
            while (!atomic_load(&state->returned)) {
                if (!before_deadline(&deadline)) goto failed;
                nanosleep(&pause, NULL);
            }
            atomic_store(&state->observed, 1);
            return NULL;
        }
        nanosleep(&pause, NULL);
    }
failed:
    /* Releasing the writer turns a setup failure or hidden retry into EOF;
     * it cannot be mistaken for the observed EINTR assertion below. */
    atomic_store(&state->observed, -1);
    close(state->writer);
    return NULL;
}
static int interrupted_io(void)
{
    struct sigaction previous, action = {.sa_handler = io_signal_handler};
    sigset_t selected, previous_mask;
    sigemptyset(&action.sa_mask);
    sigemptyset(&selected); sigaddset(&selected, SIGUSR1);
    if (sigaction(SIGUSR1, &action, &previous) ||
        pthread_sigmask(SIG_UNBLOCK, &selected, &previous_mask)) return 55;
    int result = 0;
    for (int vectored = 0; vectored < 2; vectored++) {
        int descriptors[2]; pthread_t observer;
        if (pipe(descriptors)) { result = 56; break; }
        struct interrupt_state state = {.descriptor = descriptors[0], .writer = descriptors[1],
            .number = vectored ? SYS_readv : SYS_read, .tid = (int)syscall(SYS_gettid)};
        io_signal_seen = 0;
        unsigned char bytes[4]; memset(bytes, 0xcc, sizeof bytes);
        struct iovec vector = {bytes, sizeof bytes};
        if (pthread_create(&observer, NULL, interrupt_observer, &state)) { result = 57; break; }
        errno = 0;
        ssize_t count = vectored ? readv(descriptors[0], &vector, 1) : read(descriptors[0], bytes, sizeof bytes);
        int error = errno;
        atomic_store(&state.returned, 1);
        if (pthread_join(observer, NULL) || atomic_load(&state.observed) != 1 ||
            count != -1 || error != EINTR || !io_signal_seen) { result = 58; break; }
        for (size_t index = 0; index < sizeof bytes; index++)
            if (bytes[index] != 0xcc) result = 59;
        if (write(descriptors[1], "x", 1) != 1 || read(descriptors[0], bytes, sizeof bytes) != 1 ||
            bytes[0] != 'x' || close(descriptors[0]) || close(descriptors[1])) result = 60;
        if (result) break;
    }
    if (pthread_sigmask(SIG_SETMASK, &previous_mask, NULL) || sigaction(SIGUSR1, &previous, NULL)) return 61;
    return result;
}

/* Scalar/vector checks share the same kernel files and pipe capacities as
 * the Rust facade tests; short counts never stand for a completed retry loop. */
static int io_boundaries(int fd)
{
    unsigned char bytes[8];
    off_t position = lseek(fd, 0, SEEK_CUR);
    struct iovec empty[1025] = {{0}};
    const off_t invalid[] = {INT64_MIN, -1};
    for (size_t index = 0; index < sizeof invalid / sizeof invalid[0]; index++) {
        memset(bytes, 0xcc, sizeof bytes);
        if (!expect_error(pread(fd, bytes, sizeof bytes, invalid[index]), EINVAL) ||
            !expect_error(pwrite(fd, "x", 1, invalid[index]), EINVAL) ||
            !expect_error(pwrite(fd, "", 0, invalid[index]), EINVAL)) return 40;
        for (size_t byte = 0; byte < sizeof bytes; byte++)
            if (bytes[byte] != 0xcc) return 41;
    }
    if (pread(fd, bytes, 0, INT64_MAX) != 0 || pwrite(fd, "", 0, INT64_MAX) != 0 ||
        !expect_error(pread(fd, bytes, sizeof bytes, INT64_MAX), EINVAL) ||
        !expect_error(pwrite(fd, "x", 1, INT64_MAX), EINVAL) ||
        lseek(fd, 0, SEEK_CUR) != position) return 42;
    const off_t high_offset = ((off_t)1 << 32) + 7;
    if (pwrite(fd, "hi", 2, high_offset) != 2 ||
        pread(fd, bytes, sizeof bytes, high_offset) != 2 || memcmp(bytes, "hi", 2) ||
        pread(fd, bytes, 2, 7) != 2 || bytes[0] || bytes[1] ||
        lseek(fd, 0, SEEK_CUR) != position) return 62;
    if (readv(fd, empty, 0) != 0 || writev(fd, empty, 0) != 0 ||
        readv(fd, empty, 1024) != 0 || writev(fd, empty, 1024) != 0 ||
        !expect_error(readv(fd, empty, 1025), EINVAL) ||
        !expect_error(writev(fd, empty, 1025), EINVAL) ||
        preadv(fd, empty, 1024, 0) != 0 || pwritev(fd, empty, 1024, 0) != 0 ||
        !expect_error(preadv(fd, empty, 1025, 0), EINVAL) ||
        !expect_error(pwritev(fd, empty, 1025, 0), EINVAL)) return 43;

    for (int vectored = 0; vectored < 2; vectored++) {
        int descriptors[2];
        if (pipe2(descriptors, O_NONBLOCK) != 0) return 44;
        int capacity = fcntl(descriptors[1], F_GETPIPE_SZ);
        if (capacity <= 0) return 45;
        size_t length = (size_t)capacity + 4096;
        size_t split = (size_t)capacity / 2 + 1;
        unsigned char *source = malloc(length), *received = calloc(length, 1);
        if (!source || !received) return 46;
        memset(source, 'a', split); memset(source + split, 'b', length - split);
        struct iovec writes[] = {{source, split}, {source + split, length - split}};
        ssize_t count = vectored ? writev(descriptors[1], writes, 2) : write(descriptors[1], source, length);
        if (count != capacity || !expect_error(write(descriptors[1], "x", 1), EAGAIN) ||
            !expect_error(writev(descriptors[1], writes, 2), EAGAIN) ||
            read(descriptors[0], received, length) != count || memcmp(source, received, (size_t)count)) return 47;
        for (size_t index = (size_t)count; index < length; index++)
            if (received[index]) return 48;
        free(source); free(received);
        memset(bytes, 0xcc, sizeof bytes);
        if (!expect_error(read(descriptors[0], bytes, sizeof bytes), EAGAIN)) return 49;
        struct iovec reads[] = {{bytes, 2}, {bytes + 2, 4}};
        if (!expect_error(readv(descriptors[0], reads, 2), EAGAIN)) return 50;
        for (size_t index = 0; index < sizeof bytes; index++)
            if (bytes[index] != 0xcc) return 51;
        if (write(descriptors[1], "abcde", 5) != 5 || readv(descriptors[0], reads, 2) != 5 ||
            memcmp(bytes, "abcde", 5) || bytes[5] != 0xcc ||
            read(descriptors[0], bytes, 0) != 0 || close(descriptors[1]) != 0 ||
            readv(descriptors[0], reads, 2) != 0 || read(descriptors[0], bytes, sizeof bytes) != 0 ||
            close(descriptors[0]) != 0) return 52;
    }
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets)) return 53;
    struct iovec writes[] = {{"ab", 2}, {"cde", 3}};
    if (writev(sockets[0], writes, 2) != 5 || read(sockets[1], bytes, sizeof bytes) != 5 ||
        memcmp(bytes, "abcde", 5) || !expect_error(read(sockets[1], bytes, sizeof bytes), EAGAIN) ||
        close(sockets[0]) || read(sockets[1], bytes, sizeof bytes) != 0 || close(sockets[1])) return 54;
    return 0;
}

int main(void)
{
    static const char name[] = "crabc-x86-file-position-reference";
    static const char sparse_name[] = "crabc-x86-file-position-sparse";
    static const unsigned char payload[] = {'c', 'r', 'a', 'b', 'c', '!'};
    int fd = -1;
    int sparse_fd = -1;
    int pipe_fds[2] = {-1, -1};

    fd = memfd_create(name, MFD_CLOEXEC);
    if (fd < 0)
        return 10;
    if (write(fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload))
        return 11;

    /* Confirm the raw x86 syscall boundary before the musl position checks. */
    if (syscall(SYS_lseek, fd, 0L, SEEK_SET) != 0)
        return 12;
    if (lseek(fd, (off_t)1, SEEK_SET) != (off_t)1)
        return 13;
    if (lseek(fd, (off_t)2, SEEK_CUR) != (off_t)3)
        return 14;
    if (lseek(fd, (off_t)-1, SEEK_END) != (off_t)5)
        return 15;

    /* These prove accepted sync requests only, not host durability policy. */
    if (fsync(fd) != 0 || lseek(fd, 0, SEEK_CUR) != (off_t)5)
        return 16;
    if (fdatasync(fd) != 0 || lseek(fd, 0, SEEK_CUR) != (off_t)5)
        return 17;

    sparse_fd = memfd_create(sparse_name, MFD_CLOEXEC);
    if (sparse_fd < 0)
        return 18;
    if (lseek(sparse_fd, 4096, SEEK_SET) != (off_t)4096)
        return 19;
    if (write(sparse_fd, "tail", 4) != 4)
        return 20;
    if (lseek(sparse_fd, 0, SEEK_DATA) != (off_t)4096)
        return 21;
    if (lseek(sparse_fd, 0, SEEK_HOLE) != 0)
        return 22;

    errno = 0;
    if (!expect_error(lseek(fd, 0, 0x7fff), EINVAL))
        return 23;
    errno = 0;
    if (!expect_error(syscall(SYS_lseek, fd, INT64_MIN, SEEK_SET), EINVAL))
        return 24;
    errno = 0;
    if (!expect_error(lseek(fd, INT64_MIN, SEEK_DATA), ENXIO))
        return 25;
    errno = 0;
    if (!expect_error(lseek(fd, INT64_MIN, SEEK_HOLE), ENXIO))
        return 26;
    if (pipe(pipe_fds) != 0)
        return 27;
    errno = 0;
    if (!expect_error(lseek(pipe_fds[0], 0, SEEK_SET), ESPIPE))
        return 28;
    errno = 0;
    if (!expect_error(lseek(-1, 0, SEEK_SET), EBADF))
        return 29;
    errno = 0;
    if (!expect_error(fsync(-1), EBADF))
        return 30;
    errno = 0;
    if (!expect_error(fdatasync(-1), EBADF))
        return 31;

    int io_result = interrupted_io();
    if (io_result) return io_result;
    io_result = io_boundaries(fd);
    if (io_result) return io_result;

    if (close(pipe_fds[0]) != 0 || close(pipe_fds[1]) != 0 ||
        close(sparse_fd) != 0 || close(fd) != 0)
        return 32;

    puts("syscalls=lseek:8,fsync:74,fdatasync:75 off_t=signed64 positions=start1:current3:end5 sparse=data4096:hole0 sync=memfd-position-stable over-i64=SEEK_SET:EINVAL,SEEK_DATA/HOLE:ENXIO errors=EINVAL,ENXIO,ESPIPE,EBADF");
    return 0;
}
