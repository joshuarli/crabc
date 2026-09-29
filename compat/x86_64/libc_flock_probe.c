/* Static crabc-libc x86-64 open-description flock fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through a freestanding executable linked solely with the selected
 * crabc archive. It records shared/exclusive compatibility and nonblocking
 * conflicts across separate opens, duplicate release, inherited ownership
 * after fork and parent close, stale errno on success, and EINVAL/EBADF. The
 * ordered records are compared byte for byte across the two executables.
 * It excludes fcntl record locks, lockf, generic C descriptor/path policy, CRT,
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
_Static_assert(EWOULDBLOCK == EAGAIN, "Linux lock-conflict errno alias");
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

static size_t append_number(char *output, size_t length, int number)
{
    char digits[12];
    size_t count = 0;
    unsigned int magnitude;

    if (number < 0) {
        output[length++] = '-';
        magnitude = (unsigned int)(-(long)number);
    } else {
        magnitude = (unsigned int)number;
    }
    do {
        digits[count++] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude != 0);
    while (count != 0)
        output[length++] = digits[--count];
    return length;
}

/* A single raw write keeps each parent/child observation as one ordered record. */
static int observed_flock(const char *case_name, int descriptor, int operation,
    int initial_errno, int expected_result, int expected_errno)
{
    char record[128];
    size_t length = 0;
    size_t index;
    int result;
    int error;

    errno = initial_errno;
    result = flock(descriptor, operation);
    error = errno;
    for (index = 0; case_name[index] != '\0'; ++index)
        record[length++] = case_name[index];
    record[length++] = ' ';
    length = append_number(record, length, result);
    record[length++] = ' ';
    length = append_number(record, length, error);
    record[length++] = '\n';
    if (raw_syscall3(SYS_write, 1, (long)(void *)record, length) != (long)length)
        return -1;
    return result == expected_result && error == expected_errno ? 0 : -1;
}

static void child_case(const struct fixture_file *file,
    const struct fixture_pipes *pipes)
{
    int descriptor;
    int status = 0;

    descriptor = (int)raw_syscall3(
        SYS_open, (long)(void *)file->path, O_RDWR, 0600);
    if (descriptor < 0)
        raw_exit(3);

    if (observed_flock("child-separate-exclusive-conflict", descriptor,
            LOCK_EX | LOCK_NB, 0, -1, EWOULDBLOCK) != 0)
        status = 4;
    if (status == 0 && write_token(pipes->child_to_parent[1], 'C') != 0)
        status = 5;
    if (status == 0 && read_token(pipes->parent_to_child[0], 'R') != 0)
        status = 6;
    if (status == 0 && observed_flock("child-inherited-after-parent-close",
            descriptor, LOCK_EX | LOCK_NB, 0, -1, EWOULDBLOCK) != 0)
        status = 7;
    if (status == 0 && observed_flock("child-inherited-duplicate-unlock",
            file->duplicate, LOCK_UN | LOCK_NB, ERANGE, 0, ERANGE) != 0)
        status = 8;
    if (status == 0 && observed_flock("child-separate-exclusive-acquire",
            descriptor, LOCK_EX | LOCK_NB, EDOM, 0, EDOM) != 0)
        status = 9;
    if (raw_syscall1(SYS_close, file->descriptor) != 0 && status == 0)
        status = 10;
    if (raw_syscall1(SYS_close, file->duplicate) != 0 && status == 0)
        status = 11;
    if (status == 0 && write_token(pipes->child_to_parent[1], 'S') != 0)
        status = 12;
    if (status == 0 && read_token(pipes->parent_to_child[0], 'U') != 0)
        status = 13;
    if (status == 0 && observed_flock("child-exclusive-unlock", descriptor,
            LOCK_UN | LOCK_NB, E2BIG, 0, E2BIG) != 0)
        status = 14;
    if (status == 0 && write_token(pipes->child_to_parent[1], 'D') != 0)
        status = 15;
    if (raw_syscall1(SYS_close, descriptor) != 0 && status == 0)
        status = 16;
    if (status != 0)
        (void)write_token(pipes->child_to_parent[1], 'X');
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
    if (observed_flock("invalid-descriptor", -1, LOCK_EX | LOCK_NB,
            0, -1, EBADF) != 0)
        return 1;
    if (observed_flock("invalid-operation", descriptor, LOCK_EX | 0x10,
            0, -1, EINVAL) != 0)
        return 2;
    return 0;
}

int crabc_x86_64_flock_probe(void)
{
    struct fixture_file file;
    struct fixture_pipes pipes;
    pid_t child;
    int observer = -1;
    int transient_duplicate = -1;
    int status = 0;

    if (setup_file(&file) != 0)
        return 1;
    if (setup_pipes(&pipes) != 0) {
        (void)cleanup_file(&file);
        return 2;
    }
    if (observed_flock("parent-initial-shared", file.descriptor,
            LOCK_SH | LOCK_NB, E2BIG, 0, E2BIG) != 0)
        status = 3;
    if (status == 0) {
        file.duplicate = (int)raw_syscall1(SYS_dup, file.descriptor);
        if (file.duplicate < 0)
            status = 4;
    }
    if (status == 0) {
        observer = (int)raw_syscall3(
            SYS_open, (long)(void *)file.path, O_RDWR, 0600);
        if (observer < 0)
            status = 5;
    }
    if (status == 0 && observed_flock("separate-shared-compatible",
            observer, LOCK_SH | LOCK_NB, ERANGE, 0, ERANGE) != 0)
        status = 6;
    if (status == 0 && observed_flock("separate-exclusive-conflict",
            observer, LOCK_EX | LOCK_NB, 0, -1, EWOULDBLOCK) != 0)
        status = 7;
    if (status == 0 && observed_flock("duplicate-releases-shared",
            file.duplicate, LOCK_UN | LOCK_NB, EDOM, 0, EDOM) != 0)
        status = 8;
    if (status == 0 && observed_flock("separate-exclusive-after-duplicate",
            observer, LOCK_EX | LOCK_NB, EOVERFLOW, 0, EOVERFLOW) != 0)
        status = 9;
    if (status == 0 && observed_flock("original-shared-conflicts",
            file.descriptor, LOCK_SH | LOCK_NB, 0, -1, EWOULDBLOCK) != 0)
        status = 10;
    if (status == 0 && observed_flock("separate-exclusive-unlock",
            observer, LOCK_UN | LOCK_NB, ENOTRECOVERABLE, 0,
            ENOTRECOVERABLE) != 0)
        status = 11;
    if (status == 0 && observed_flock("duplicate-reacquires-shared",
            file.duplicate, LOCK_SH | LOCK_NB, E2BIG, 0, E2BIG) != 0)
        status = 12;
    if (status == 0 && observed_flock("separate-shared-reacquire",
            observer, LOCK_SH | LOCK_NB, ERANGE, 0, ERANGE) != 0)
        status = 13;
    if (status == 0 && observed_flock("separate-shared-unlock", observer,
            LOCK_UN | LOCK_NB, EDOM, 0, EDOM) != 0)
        status = 14;
    if (status == 0) {
        transient_duplicate = (int)raw_syscall1(SYS_dup, file.descriptor);
        if (transient_duplicate < 0 ||
            raw_syscall1(SYS_close, transient_duplicate) != 0)
            status = 15;
        transient_duplicate = -1;
    }
    if (status == 0 && observed_flock("duplicate-close-keeps-shared",
            observer, LOCK_EX | LOCK_NB, 0, -1, EWOULDBLOCK) != 0)
        status = 16;
    if (observer >= 0 && raw_syscall1(SYS_close, observer) != 0 && status == 0)
        status = 17;
    observer = -1;

    child = status == 0 ? (pid_t)raw_syscall0(SYS_fork) : -1;
    if (child < 0 && status == 0)
        status = 18;
    if (child == 0)
        child_case(&file, &pipes);

    if (status == 0) {
        (void)raw_syscall1(SYS_close, pipes.child_to_parent[1]);
        pipes.child_to_parent[1] = -1;
        (void)raw_syscall1(SYS_close, pipes.parent_to_child[0]);
        pipes.parent_to_child[0] = -1;
        if (read_token(pipes.child_to_parent[0], 'C') != 0)
            status = 19;
    }
    if (status == 0) {
        if (raw_syscall1(SYS_close, file.descriptor) != 0)
            status = 20;
        file.descriptor = -1;
        if (raw_syscall1(SYS_close, file.duplicate) != 0 && status == 0)
            status = 21;
        file.duplicate = -1;
    }
    if (status == 0 && write_token(pipes.parent_to_child[1], 'R') != 0)
        status = 22;
    if (status == 0 && read_token(pipes.child_to_parent[0], 'S') != 0)
        status = 23;
    if (status == 0) {
        observer = (int)raw_syscall3(
            SYS_open, (long)(void *)file.path, O_RDWR, 0600);
        if (observer < 0)
            status = 24;
    }
    if (status == 0 && observed_flock("parent-shared-conflicts-child",
            observer, LOCK_SH | LOCK_NB, 0, -1, EWOULDBLOCK) != 0)
        status = 25;
    if (observer >= 0 && raw_syscall1(SYS_close, observer) != 0 && status == 0)
        status = 26;
    observer = -1;
    if (status == 0 && write_token(pipes.parent_to_child[1], 'U') != 0)
        status = 27;
    if (status == 0 && read_token(pipes.child_to_parent[0], 'D') != 0)
        status = 28;
    if (status == 0) {
        file.descriptor = (int)raw_syscall3(
            SYS_open, (long)(void *)file.path, O_RDWR, 0600);
        if (file.descriptor < 0)
            status = 29;
    }
    if (status == 0)
        status = check_errors(file.descriptor) == 0 ? 0 : 30;
    if (status == 0 && observed_flock("parent-reacquires-after-child",
            file.descriptor, LOCK_SH | LOCK_NB, EOVERFLOW, 0,
            EOVERFLOW) != 0)
        status = 31;
    if (status == 0 && observed_flock("parent-final-unlock",
            file.descriptor, LOCK_UN | LOCK_NB, ENOTRECOVERABLE, 0,
            ENOTRECOVERABLE) != 0)
        status = 32;
    if (status == 0) {
        if (wait_child(child) != 0)
            status = 33;
    } else {
        terminate_child(child);
    }
    (void)close_pipe_pair(pipes.child_to_parent);
    (void)close_pipe_pair(pipes.parent_to_child);
    if (cleanup_file(&file) != 0 && status == 0)
        status = 34;
    return status;
}

#ifndef CRABC_FLOCK_FREESTANDING
int main(void)
{
    return crabc_x86_64_flock_probe();
}
#endif
