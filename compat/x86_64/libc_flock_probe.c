/* Static crabc-libc x86-64 nonblocking OFD flock fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through a freestanding executable linked solely with the selected
 * crabc archive. It proves nonblocking shared/exclusive flock operations on
 * distinct open file descriptions, conflict and release ordering, stale
 * errno on success, and direct EINVAL/EBADF errors. It deliberately excludes
 * fcntl record locks, lockf, generic C descriptor/path policy, CRT,
 * pthread/TLS lifecycle, loader, sysroot, and public x86 support.
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
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/types.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(int) == 4 && sizeof(pid_t) == 4,
    "x86 flock scalar widths");
_Static_assert(SYS_open == 2 && SYS_close == 3 && SYS_pipe == 22 &&
    SYS_flock == 73 && SYS_fork == 57 && SYS_wait4 == 61 &&
    SYS_getpid == 39 && SYS_unlink == 87 && SYS_dup == 32 && SYS_kill == 62,
    "x86 selected flock fixture syscall numbers");
_Static_assert(LOCK_SH == 1 && LOCK_EX == 2 && LOCK_NB == 4 &&
    LOCK_UN == 8, "x86 selected flock operation bits");
_Static_assert(__builtin_types_compatible_p(__typeof__(&flock),
    int (*)(int, int)), "flock declaration");

struct fixture_file {
    int descriptor;
    int duplicate;
    char path[88];
};

struct fixture_pipes {
    int child_to_parent[2];
    int parent_to_child[2];
};

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long argument_one)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one) : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long argument_one, long argument_two)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument_one, long argument_two,
    long argument_three)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument_one, long argument_two,
    long argument_three, long argument_four)
{
    long result;
    register long register_four __asm__("r10") = argument_four;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(register_four)
        : "rcx", "r11", "memory");
    return result;
}

static void raw_exit(int status) __attribute__((noreturn));

static void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    for (;;)
        __asm__ volatile("pause" ::: "memory");
}

static int make_path(char *output, size_t capacity, long process_id)
{
    static const char prefix[] = "/tmp/crabc-x86-64-flock-";
    char digits[20];
    size_t length = 0;
    size_t digits_length = 0;
    size_t index;

    if (process_id <= 0)
        return -1;
    for (index = 0; prefix[index] != '\0'; ++index) {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = prefix[index];
    }
    do {
        if (digits_length == sizeof(digits))
            return -1;
        digits[digits_length++] = (char)('0' + process_id % 10);
        process_id /= 10;
    } while (process_id != 0);
    while (digits_length != 0) {
        if (length + 1 >= capacity)
            return -1;
        output[length++] = digits[--digits_length];
    }
    output[length] = '\0';
    return 0;
}

static int setup_file(struct fixture_file *file)
{
    file->descriptor = -1;
    file->duplicate = -1;
    if (make_path(file->path, sizeof(file->path), raw_syscall0(SYS_getpid)) != 0)
        return -1;
    file->descriptor = (int)raw_syscall3(
        SYS_open, (long)(void *)file->path, O_CREAT | O_EXCL | O_RDWR, 0600);
    return file->descriptor < 0 ? -1 : 0;
}

static int cleanup_file(struct fixture_file *file)
{
    int result = 0;

    if (file->descriptor >= 0 &&
        raw_syscall1(SYS_close, file->descriptor) != 0)
        result = -1;
    if (file->duplicate >= 0 &&
        raw_syscall1(SYS_close, file->duplicate) != 0)
        result = -1;
    if (raw_syscall1(SYS_unlink, (long)(void *)file->path) != 0)
        result = -1;
    file->descriptor = -1;
    return result;
}

static int close_pipe_pair(int pair[2])
{
    int result = 0;

    if (pair[0] >= 0 && raw_syscall1(SYS_close, pair[0]) != 0)
        result = -1;
    if (pair[1] >= 0 && raw_syscall1(SYS_close, pair[1]) != 0)
        result = -1;
    pair[0] = -1;
    pair[1] = -1;
    return result;
}

static int setup_pipes(struct fixture_pipes *pipes)
{
    pipes->child_to_parent[0] = -1;
    pipes->child_to_parent[1] = -1;
    pipes->parent_to_child[0] = -1;
    pipes->parent_to_child[1] = -1;
    if (raw_syscall1(SYS_pipe, (long)(void *)pipes->child_to_parent) != 0)
        return -1;
    if (raw_syscall1(SYS_pipe, (long)(void *)pipes->parent_to_child) != 0) {
        (void)close_pipe_pair(pipes->child_to_parent);
        return -1;
    }
    return 0;
}

static int write_token(int descriptor, char token)
{
    long result;

    do {
        result = raw_syscall3(SYS_write, descriptor, (long)(void *)&token, 1);
    } while (result == -EINTR);
    return result == 1 ? 0 : -1;
}

static int read_token(int descriptor, char expected)
{
    char token;
    long result;

    do {
        result = raw_syscall3(SYS_read, descriptor, (long)(void *)&token, 1);
    } while (result == -EINTR);
    return result == 1 && token == expected ? 0 : -1;
}

static int is_lock_conflict(int error)
{
    return error == EWOULDBLOCK || error == EAGAIN;
}

static int child_case(const struct fixture_file *file,
    const struct fixture_pipes *pipes, pid_t parent)
{
    int descriptor;
    int status = 0;

    if (raw_syscall1(SYS_close, file->descriptor) != 0)
        return 1;
    if (raw_syscall1(SYS_close, file->duplicate) != 0)
        return 2;
    descriptor = (int)raw_syscall3(
        SYS_open, (long)(void *)file->path, O_RDWR, 0600);
    if (descriptor < 0)
        return 3;

    errno = 0;
    if (flock(descriptor, LOCK_EX | LOCK_NB) != -1 ||
        !is_lock_conflict(errno))
        status = 4;
    if (status == 0 && write_token(pipes->child_to_parent[1], 'C') != 0)
        status = 5;
    if (status == 0 && read_token(pipes->parent_to_child[0], 'R') != 0)
        status = 6;
    if (status == 0) {
        errno = ERANGE;
        if (flock(descriptor, LOCK_EX | LOCK_NB) != 0 || errno != ERANGE)
            status = 7;
    }
    if (status == 0 && write_token(pipes->child_to_parent[1], 'S') != 0)
        status = 8;
    if (status == 0 && read_token(pipes->parent_to_child[0], 'U') != 0)
        status = 9;
    if (status == 0) {
        errno = EDOM;
        if (flock(descriptor, LOCK_UN | LOCK_NB) != 0 || errno != EDOM)
            status = 10;
    }
    if (status == 0 && write_token(pipes->child_to_parent[1], 'D') != 0)
        status = 11;
    if (raw_syscall1(SYS_close, descriptor) != 0 && status == 0)
        status = 12;
    if (status != 0)
        (void)write_token(pipes->child_to_parent[1], 'X');
    (void)parent;
    raw_exit(status);
}

static int wait_child(pid_t child)
{
    int status = -1;
    long result;

    do {
        result = raw_syscall4(SYS_wait4, child, (long)(void *)&status, 0, 0);
    } while (result == -EINTR);
    return result == child && status == 0 ? 0 : -1;
}

static void terminate_child(pid_t child)
{
    if (child <= 0)
        return;
    (void)raw_syscall2(SYS_kill, child, 9);
    (void)wait_child(child);
}

static int check_errors(int descriptor)
{
    errno = 0;
    if (flock(-1, LOCK_EX | LOCK_NB) != -1 || errno != EBADF)
        return 1;
    errno = 0;
    if (flock(descriptor, LOCK_EX | 0x10) != -1 || errno != EINVAL)
        return 2;
    return 0;
}

int crabc_x86_64_flock_probe(void)
{
    struct fixture_file file;
    struct fixture_pipes pipes;
    pid_t child;
    int observer = -1;
    int status = 0;

    if (setup_file(&file) != 0)
        return 1;
    if (setup_pipes(&pipes) != 0) {
        (void)cleanup_file(&file);
        return 2;
    }
    errno = E2BIG;
    if (flock(file.descriptor, LOCK_SH | LOCK_NB) != 0 || errno != E2BIG)
        status = 3;
    if (status == 0) {
        file.duplicate = (int)raw_syscall1(SYS_dup, file.descriptor);
        if (file.duplicate < 0)
            status = 4;
    }
    child = status == 0 ? (pid_t)raw_syscall0(SYS_fork) : -1;
    if (child < 0)
        status = 5;
    if (child == 0)
        child_case(&file, &pipes, (pid_t)raw_syscall0(SYS_getpid));

    if (status == 0) {
        (void)raw_syscall1(SYS_close, pipes.child_to_parent[1]);
        pipes.child_to_parent[1] = -1;
        (void)raw_syscall1(SYS_close, pipes.parent_to_child[0]);
        pipes.parent_to_child[0] = -1;
        if (read_token(pipes.child_to_parent[0], 'C') != 0)
            status = 6;
    }
    if (status == 0) {
        errno = ERANGE;
        if (flock(file.duplicate, LOCK_UN | LOCK_NB) != 0 || errno != ERANGE)
            status = 7;
        if (raw_syscall1(SYS_close, file.duplicate) != 0 && status == 0)
            status = 8;
        file.duplicate = -1;
    }
    if (status == 0 && write_token(pipes.parent_to_child[1], 'R') != 0)
        status = 9;
    if (status == 0 && read_token(pipes.child_to_parent[0], 'S') != 0)
        status = 10;
    if (status == 0) {
        observer = (int)raw_syscall3(
            SYS_open, (long)(void *)file.path, O_RDWR, 0600);
        if (observer < 0)
            status = 11;
    }
    if (status == 0) {
        errno = 0;
        if (flock(observer, LOCK_SH | LOCK_NB) != -1 ||
            !is_lock_conflict(errno))
            status = 12;
    }
    if (observer >= 0 && raw_syscall1(SYS_close, observer) != 0 && status == 0)
        status = 13;
    observer = -1;
    if (status == 0 && write_token(pipes.parent_to_child[1], 'U') != 0)
        status = 14;
    if (status == 0 && read_token(pipes.child_to_parent[0], 'D') != 0)
        status = 15;
    if (status == 0)
        status = check_errors(file.descriptor) == 0 ? 0 : 16;
    if (status == 0) {
        errno = EOVERFLOW;
        if (flock(file.descriptor, LOCK_SH | LOCK_NB) != 0 ||
            errno != EOVERFLOW)
            status = 17;
    }
    if (status == 0) {
        errno = ENOTRECOVERABLE;
        if (flock(file.descriptor, LOCK_UN | LOCK_NB) != 0 ||
            errno != ENOTRECOVERABLE)
            status = 18;
    }
    if (status == 0) {
        if (wait_child(child) != 0)
            status = 19;
    } else {
        terminate_child(child);
    }
    (void)close_pipe_pair(pipes.child_to_parent);
    (void)close_pipe_pair(pipes.parent_to_child);
    if (cleanup_file(&file) != 0 && status == 0)
        status = 20;
    return status;
}

#ifndef CRABC_FLOCK_FREESTANDING
int main(void)
{
    return crabc_x86_64_flock_probe();
}
#endif
