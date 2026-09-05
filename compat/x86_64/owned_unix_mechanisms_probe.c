#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <stropts.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        dprintf(2, "owned-unix-mechanisms line %d errno %d\n", __LINE__, errno); \
        _exit(77); \
    } \
} while (0)

/* This local raw boundary is evidence control only. The installed candidate
 * reaches its target-local raw-syscall owner; neither program uses ambient
 * libc for the compared calls. */
static long raw6(long number, long a, long b, long c, long d, long e, long f)
{
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return result;
}

/* Linux seccomp filter records, expressed locally so the installed workload
 * does not depend on a host Linux-header include path. */
struct filter_instruction {
    unsigned short code;
    unsigned char jump_true;
    unsigned char jump_false;
    unsigned int value;
};

struct filter_program {
    unsigned short count;
    struct filter_instruction *instructions;
};

_Static_assert(sizeof(struct filter_instruction) == 8, "Linux BPF instruction ABI");
_Static_assert(sizeof(struct filter_program) == 16, "Linux BPF program ABI");

#define BPF_LOAD_SYSCALL { 0x20, 0, 0, 0 }
#define BPF_EQUAL(number) { 0x15, 0, 1, (unsigned int)(number) }
#define BPF_RETURN(value) { 0x06, 0, 0, (unsigned int)(value) }
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_RET_ALLOW 0x7fff0000U
#define SECCOMP_RET_ERRNO 0x00050000U
#define PR_SET_NO_NEW_PRIVS 38
#define PR_SET_SECCOMP 22

static void install_denied_privileged_calls(void)
{
    struct filter_instruction instructions[] = {
        BPF_LOAD_SYSCALL,
        BPF_EQUAL(SYS_mount),
        BPF_RETURN(SECCOMP_RET_ERRNO | EPERM),
        BPF_EQUAL(SYS_umount2),
        BPF_RETURN(SECCOMP_RET_ERRNO | EPERM),
        BPF_EQUAL(SYS_vhangup),
        BPF_RETURN(SECCOMP_RET_ERRNO | EPERM),
        BPF_RETURN(SECCOMP_RET_ALLOW),
    };
    struct filter_program program = {
        (unsigned short)(sizeof(instructions) / sizeof(instructions[0])),
        instructions,
    };

    CHECK(raw6(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0) == 0);
    CHECK(raw6(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0,
               (long)(intptr_t)&program, 0, 0, 0) == 0);
}

static void check_denied_result(long raw, int result)
{
    CHECK(raw == -EPERM);
    CHECK(result == -1 && errno == EPERM);
}

static void current_directory_case(void)
{
    char *name;

    if (mkdir("/physical", 0700) < 0)
        CHECK(errno == EEXIST);
    if (symlink("/physical", "/logical") < 0)
        CHECK(errno == EEXIST);
    CHECK(chdir("/logical") == 0);

    CHECK(setenv("PWD", "/logical", 1) == 0);
    errno = EDOM;
    name = get_current_dir_name();
    CHECK(name != NULL && strcmp(name, "/logical") == 0 && errno == EDOM);
    free(name);

    CHECK(setenv("PWD", "/missing", 1) == 0);
    errno = ERANGE;
    name = get_current_dir_name();
    CHECK(name != NULL && strcmp(name, "/physical") == 0 && errno == ENOENT);
    free(name);

    CHECK(setenv("PWD", "", 1) == 0);
    errno = EDOM;
    name = get_current_dir_name();
    CHECK(name != NULL && strcmp(name, "/physical") == 0 && errno == EDOM);
    free(name);

    puts("current-directory ok");
}

static void privileged_error_case(void)
{
    pid_t child = fork();
    int status;
    static const char absent[] = "/absent-mount-target";

    CHECK(child >= 0);
    if (child == 0) {
        long raw;

        install_denied_privileged_calls();

        errno = E2BIG;
        raw = raw6(SYS_mount, 0, 0, 0, 0, 0, 0);
        CHECK(errno == E2BIG);
        errno = ERANGE;
        check_denied_result(raw, mount(NULL, NULL, NULL, 0, NULL));

        errno = E2BIG;
        raw = raw6(SYS_umount2, (long)(intptr_t)absent, 0, 0, 0, 0, 0);
        CHECK(errno == E2BIG);
        errno = ERANGE;
        check_denied_result(raw, umount(absent));

        errno = E2BIG;
        raw = raw6(SYS_umount2, (long)(intptr_t)absent, -1, 0, 0, 0, 0);
        CHECK(errno == E2BIG);
        errno = ERANGE;
        check_denied_result(raw, umount2(absent, -1));

        errno = E2BIG;
        raw = raw6(SYS_vhangup, 0, 0, 0, 0, 0, 0);
        CHECK(errno == E2BIG);
        errno = ERANGE;
        check_denied_result(raw, vhangup());
        _exit(0);
    }

    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("privileged-errors ok");
}

static int terminal_fd(void)
{
    /* The runner opens a private harmless pseudo-terminal master before
     * chroot/exec and preserves it as fd 3 in every oracle/candidate run. */
    CHECK(isatty(3) == 1);
    return 3;
}

static void terminal_case(void)
{
    int fd = terminal_fd();
    int regular;

    errno = EDOM;
    CHECK(tcdrain(fd) == 0 && errno == EDOM);

    regular = open("/regular-file", O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(regular >= 0);
    errno = 0;
    CHECK(tcdrain(regular) == -1 && errno == ENOTTY);
    CHECK(close(regular) == 0);

    errno = 0;
    CHECK(tcdrain(-1) == -1 && errno == EBADF);
    puts("terminal-drain ok");
}

static atomic_int cancellation_ready;
static atomic_int cancellation_go;
static atomic_int cancellation_cleanup;

static void tcdrain_cleanup(void *ignored)
{
    (void)ignored;
    atomic_store(&cancellation_cleanup, 1);
}

static void *tcdrain_worker(void *ignored)
{
    (void)ignored;
    atomic_store(&cancellation_ready, 1);
    while (!atomic_load(&cancellation_go))
        atomic_signal_fence(memory_order_seq_cst);

    pthread_cleanup_push(tcdrain_cleanup, NULL);
    CHECK(tcdrain(terminal_fd()) == 0);
    pthread_cleanup_pop(0);
    return (void *)1;
}

static void terminal_cancellation_case(void)
{
    pthread_t worker;
    void *result = NULL;

    atomic_store(&cancellation_ready, 0);
    atomic_store(&cancellation_go, 0);
    atomic_store(&cancellation_cleanup, 0);
    CHECK(pthread_create(&worker, NULL, tcdrain_worker, NULL) == 0);
    while (!atomic_load(&cancellation_ready))
        atomic_signal_fence(memory_order_seq_cst);
    CHECK(pthread_cancel(worker) == 0);
    atomic_store(&cancellation_go, 1);
    CHECK(pthread_join(worker, &result) == 0);
    CHECK(result == PTHREAD_CANCELED && atomic_load(&cancellation_cleanup) == 1);
    puts("terminal-drain cancellation ok");
}

static void vmsplice_case(void)
{
    char source[] = "vmsplice bytes";
    char destination[sizeof(source)] = { 0 };
    struct iovec vector = { source, sizeof(source) - 1 };
    int pipefd[2];
    long raw;

    CHECK(pipe(pipefd) == 0);
    errno = EDOM;
    CHECK(vmsplice(pipefd[1], &vector, 1, 0) == (ssize_t)(sizeof(source) - 1));
    CHECK(errno == EDOM);
    CHECK(read(pipefd[0], destination, sizeof(source) - 1) == (ssize_t)(sizeof(source) - 1));
    CHECK(memcmp(destination, source, sizeof(source) - 1) == 0);
    /* The read endpoint writes user memory; the same public const-iovec
     * signature covers both directions. Keep the ranges alive until the
     * pipe transfer has completed. */
    CHECK(write(pipefd[1], source, sizeof(source) - 1) == (ssize_t)(sizeof(source) - 1));
    memset(destination, 0, sizeof(destination));
    vector.iov_base = destination;
    errno = EDOM;
    CHECK(vmsplice(pipefd[0], &vector, 1, 0) == (ssize_t)(sizeof(source) - 1));
    CHECK(errno == EDOM && memcmp(destination, source, sizeof(source) - 1) == 0);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);

    errno = E2BIG;
    raw = raw6(SYS_vmsplice, -1, (long)(intptr_t)&vector, 1, 0, 0, 0);
    CHECK(raw < 0 && raw >= -4095 && errno == E2BIG);
    errno = ERANGE;
    CHECK(vmsplice(-1, &vector, 1, 0) == -1 && errno == -raw);
    puts("vmsplice ok");
}

static void streams_case(void)
{
    int regular = open("/regular-stream-file", O_RDWR | O_CREAT | O_TRUNC, 0600);

    CHECK(regular >= 0);
    errno = EDOM;
    CHECK(isastream(terminal_fd()) == 0 && errno == EDOM);
    errno = EDOM;
    CHECK(isastream(regular) == 0 && errno == EDOM);
    CHECK(close(regular) == 0);
    errno = 0;
    CHECK(isastream(-1) == -1 && errno == EBADF);
    puts("streams ok");
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (!strcmp(argv[1], "cwd"))
        current_directory_case();
    else if (!strcmp(argv[1], "privileged-errors"))
        privileged_error_case();
    else if (!strcmp(argv[1], "terminal"))
        terminal_case();
    else if (!strcmp(argv[1], "terminal-cancel"))
        terminal_cancellation_case();
    else if (!strcmp(argv[1], "vmsplice"))
        vmsplice_case();
    else if (!strcmp(argv[1], "streams"))
        streams_case();
    else
        CHECK(0);
    return 0;
}
