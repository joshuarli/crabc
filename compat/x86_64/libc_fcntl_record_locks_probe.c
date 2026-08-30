/* Static crabc-libc x86-64 nonblocking fcntl record-lock fixture.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through a freestanding executable linked solely with the selected
 * crabc archive. It proves only F_GETLK/F_SETLK with the public 32-byte
 * struct flock record: an unlocked query, a parent-owned conflicting write
 * lock observed by a child, nonblocking conflict errors, release, stale
 * errno on success, and direct kernel errors. It is not F_SETLKW
 * cancellation, OFD locks, lockf, flock, generic fcntl, descriptor/pathname
 * policy, CRT, pthread/TLS lifecycle, loader, sysroot, or public x86 support.
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
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct flock) == 32 && _Alignof(struct flock) == 8,
    "x86 struct flock layout");
_Static_assert(offsetof(struct flock, l_type) == 0 &&
    offsetof(struct flock, l_whence) == 2 &&
    offsetof(struct flock, l_start) == 8 &&
    offsetof(struct flock, l_len) == 16 &&
    offsetof(struct flock, l_pid) == 24, "x86 struct flock offsets");
_Static_assert(SYS_open == 2 && SYS_close == 3 && SYS_fcntl == 72 &&
    SYS_fork == 57 && SYS_wait4 == 61 && SYS_getpid == 39 && SYS_unlink == 87,
    "x86 selected record-lock fixture syscall numbers");
_Static_assert(F_GETLK == 5 && F_SETLK == 6 && F_SETLKW == 7 &&
    F_RDLCK == 0 && F_WRLCK == 1 && F_UNLCK == 2,
    "x86 selected record-lock command and type values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fcntl),
    int (*)(int, int, ...)), "fcntl declaration");

struct fixture_file {
    int descriptor;
    char path[88];
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
    static const char prefix[] = "/tmp/crabc-x86-64-fcntl-record-locks-";
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
    if (make_path(file->path, sizeof(file->path), raw_syscall0(SYS_getpid)) != 0)
        return -1;
    file->descriptor = (int)raw_syscall3(
        SYS_open, (long)(void *)file->path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (file->descriptor < 0)
        return -1;
    if (raw_syscall1(SYS_unlink, (long)(void *)file->path) != 0) {
        (void)raw_syscall1(SYS_close, file->descriptor);
        file->descriptor = -1;
        return -1;
    }
    return 0;
}

static int cleanup_file(struct fixture_file *file)
{
    if (file->descriptor >= 0 && raw_syscall1(SYS_close, file->descriptor) != 0)
        return -1;
    file->descriptor = -1;
    return 0;
}

static struct flock write_lock(void)
{
    return (struct flock) {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
        .l_pid = 0,
    };
}

static int check_unlocked_query(int descriptor)
{
    struct flock query = write_lock();

    errno = E2BIG;
    if (fcntl(descriptor, F_GETLK, &query) != 0 ||
        query.l_type != F_UNLCK || errno != E2BIG)
        return 1;
    return 0;
}

static int child_observes_parent_lock(int descriptor, pid_t parent)
{
    struct flock query = write_lock();
    struct flock request = write_lock();

    errno = ERANGE;
    if (fcntl(descriptor, F_GETLK, &query) != 0 || errno != ERANGE)
        return 1;
    if (query.l_type != F_WRLCK || query.l_whence != SEEK_SET ||
        query.l_start != 0 || query.l_len != 0 || query.l_pid != parent)
        return 2;
    errno = 0;
    if (fcntl(descriptor, F_SETLK, &request) != -1 ||
        (errno != EACCES && errno != EAGAIN))
        return 3;
    return 0;
}

static int run_child_case(int descriptor, pid_t parent)
{
    long child = raw_syscall0(SYS_fork);
    int status = -1;
    long waited;

    if (child == 0)
        raw_exit(child_observes_parent_lock(descriptor, parent));
    if (child < 0)
        return 1;
    do {
        waited = raw_syscall4(SYS_wait4, child, (long)(void *)&status, 0, 0);
    } while (waited == -EINTR);
    if (waited != child)
        return 2;
    return status == 0 ? 0 : 3;
}

static int check_selected_record_lock_lifecycle(const struct fixture_file *file)
{
    struct flock lock = write_lock();
    int status;

    status = check_unlocked_query(file->descriptor);
    if (status != 0)
        return status;
    errno = E2BIG;
    if (fcntl(file->descriptor, F_SETLK, &lock) != 0 || errno != E2BIG)
        return 10;
    status = run_child_case(file->descriptor, (pid_t)raw_syscall0(SYS_getpid));
    if (status != 0)
        return 20 + status;
    lock.l_type = F_UNLCK;
    errno = ERANGE;
    if (fcntl(file->descriptor, F_SETLK, &lock) != 0 || errno != ERANGE)
        return 30;
    status = check_unlocked_query(file->descriptor);
    return status == 0 ? 0 : 40 + status;
}

static int check_errors(int descriptor)
{
    struct flock query = write_lock();
    struct flock invalid = write_lock();

    errno = 0;
    if (fcntl(-1, F_GETLK, &query) != -1 || errno != EBADF)
        return 1;
    errno = 0;
    if (fcntl(-1, F_SETLK, &query) != -1 || errno != EBADF)
        return 2;
    invalid.l_type = 99;
    errno = 0;
    if (fcntl(descriptor, F_SETLK, &invalid) != -1 || errno != EINVAL)
        return 3;
    return 0;
}

#ifdef CRABC_FCNTL_RECORD_LOCKS_FREESTANDING
static int check_unselected_blocking_form(int descriptor)
{
    struct flock lock = write_lock();

    /* Pinned musl selects F_SETLKW as a cancellation point; this bounded
     * candidate deliberately rejects it before observing the pointer vararg. */
    errno = 0;
    if (fcntl(descriptor, F_SETLKW, &lock) != -1 || errno != EINVAL)
        return 1;
    return 0;
}
#endif

int crabc_x86_64_fcntl_record_locks_probe(void)
{
    struct fixture_file file;
    int status;
    int cleanup_status;

    if (setup_file(&file) != 0)
        return 1;
    status = check_selected_record_lock_lifecycle(&file);
    if (status == 0)
        status = check_errors(file.descriptor);
#ifdef CRABC_FCNTL_RECORD_LOCKS_FREESTANDING
    if (status == 0)
        status = check_unselected_blocking_form(file.descriptor);
#endif
    cleanup_status = cleanup_file(&file);
    if (status != 0)
        return 10 + status;
    return cleanup_status == 0 ? 0 : 90;
}

#ifndef CRABC_FCNTL_RECORD_LOCKS_FREESTANDING
int main(void)
{
    return crabc_x86_64_fcntl_record_locks_probe();
}
#endif
