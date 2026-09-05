/* Installed x86 POSIX environment lifecycle differential workload.
 *
 * The caller serializes every environment access. The fixture intentionally
 * creates no concurrent environment mutation: returned getenv values and direct
 * environ storage remain valid only across the explicit non-mutating intervals
 * below. Allocation failure uses only a disposable-child seccomp filter.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **__environ;
extern char **_environ;
extern char **___environ;

extern char **environ;

typedef char *(*getenv_signature)(const char *);
typedef int (*setenv_signature)(const char *, const char *, int);
typedef int (*putenv_signature)(char *);
typedef int (*unsetenv_signature)(const char *);
typedef int (*clearenv_signature)(void);
typedef int (*posix_spawn_signature)(pid_t *, const char *,
    const posix_spawn_file_actions_t *, const posix_spawnattr_t *,
    char *const[], char *const[]);

_Static_assert(__builtin_types_compatible_p(__typeof__(&getenv),
    getenv_signature), "getenv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setenv),
    setenv_signature), "setenv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&putenv),
    putenv_signature), "putenv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&unsetenv),
    unsetenv_signature), "unsetenv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clearenv),
    clearenv_signature), "clearenv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_spawn),
    posix_spawn_signature), "posix_spawn declaration");
_Static_assert(sizeof(char *) == 8 && _Alignof(char *) == 8,
    "x86 LP64 environment vector ABI");
_Static_assert(sizeof(long) == 8 && sizeof(uintptr_t) == sizeof(void *),
    "x86 LP64 variadic syscall word ABI");

static void fail(void)
{
    _Exit(125);
}

#define CHECK(expression) do { if (!(expression)) fail(); } while (0)

enum {
    CRABC_BPF_LD = 0x00,
    CRABC_BPF_W = 0x00,
    CRABC_BPF_ABS = 0x20,
    CRABC_BPF_JMP = 0x05,
    CRABC_BPF_JEQ = 0x10,
    CRABC_BPF_K = 0x00,
    CRABC_BPF_RET = 0x06,
    CRABC_SECCOMP_SET_MODE_FILTER = 1,
    CRABC_SECCOMP_RET_ALLOW = 0x7fff0000U,
    CRABC_SECCOMP_RET_ERRNO = 0x00050000U,
    CRABC_FAILURE_VALUE_BYTES = 2 * 1024 * 1024,
};

struct crabc_bpf_instruction {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t value;
};

struct crabc_bpf_program {
    uint16_t length;
    struct crabc_bpf_instruction *instructions;
};

#define CRABC_BPF_STATEMENT(code, value) { (code), 0, 0, (value) }
#define CRABC_BPF_JUMP(code, value, jump_true, jump_false) \
    { (code), (jump_true), (jump_false), (value) }

/* The source owner has no allocation-failure switch. A disposable child
 * instead blocks only future allocation-growth syscalls with ENOMEM. */
static void deny_allocation_growth(void)
{
    struct crabc_bpf_instruction instructions[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_mmap, 2, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_brk, 1, 0),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | ENOMEM),
    };
    struct crabc_bpf_program program = {
        sizeof(instructions) / sizeof(instructions[0]),
        instructions,
    };

    /* Both interfaces are variadic. Keep scalar arguments at their kernel
     * word width and carry the program pointer through uintptr_t explicitly. */
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) == 0);
    CHECK(syscall((long)SYS_seccomp, (long)CRABC_SECCOMP_SET_MODE_FILTER,
        0L, (long)(uintptr_t)&program) == 0);
}

static int text_equal(const char *left, const char *right)
{
    if (left == NULL || right == NULL)
        return left == right;
    while (*left || *right) {
        if (*left != *right)
            return 0;
        left++;
        right++;
    }
    return 1;
}

static int aliases_match(char **expected)
{
    return &environ == &__environ && &environ == &_environ &&
        &environ == &___environ && environ == expected &&
        __environ == expected && _environ == expected &&
        ___environ == expected;
}

static void wait_for_exit(pid_t child, int expected)
{
    int status = 0;

    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}

static void check_replacement_removal_clear(void)
{
    static char base[] = "BASE=initial";
    static char duplicate_first[] = "DUP=first";
    static char duplicate_second[] = "DUP=second";
    static char beta[] = "BETA=initial";
    static char *direct_environment[] = {
        base,
        duplicate_first,
        duplicate_second,
        beta,
        NULL,
    };
    char remove_duplicate[] = "DUP";
    char copied_value[] = "copied";

    environ = direct_environment;
    CHECK(aliases_match(direct_environment));
    CHECK(text_equal(getenv("DUP"), "first"));
    CHECK(setenv("DUP", "replacement", 1) == 0);
    CHECK(environ == direct_environment);
    CHECK(text_equal(direct_environment[1], "DUP=replacement"));
    CHECK(text_equal(direct_environment[2], "DUP=second"));
    CHECK(text_equal(getenv("DUP"), "replacement"));
    CHECK(unsetenv(remove_duplicate) == 0);
    CHECK(environ == direct_environment && getenv("DUP") == NULL);
    CHECK(text_equal(direct_environment[0], "BASE=initial"));
    CHECK(text_equal(direct_environment[1], "BETA=initial"));
    CHECK(direct_environment[2] == NULL);

    errno = EINTR;
    CHECK(setenv("BETA", "ignored", 0) == 0);
    CHECK(errno == EINTR && text_equal(getenv("BETA"), "initial"));
    CHECK(setenv("BETA", copied_value, 1) == 0);
    copied_value[0] = 'X';
    CHECK(text_equal(getenv("BETA"), "copied"));

    CHECK(clearenv() == 0);
    CHECK(aliases_match(NULL));
    CHECK(getenv("BASE") == NULL && getenv("BETA") == NULL);
}

static void check_direct_environ_and_borrowed_value(void)
{
    static char keep[] = "KEEP=initial";
    static char drop[] = "DROP=gone";
    static char *direct_environment[] = { keep, drop, NULL };
    char borrowed_entry[] = "BORROW=first";
    char *borrowed;

    environ = direct_environment;
    CHECK(aliases_match(direct_environment));
    borrowed = getenv("KEEP");
    CHECK(borrowed == keep + 5 && text_equal(borrowed, "initial"));
    borrowed[0] = 'I';
    CHECK(text_equal(getenv("KEEP"), "Initial"));
    CHECK(unsetenv("DROP") == 0);
    CHECK(environ == direct_environment && direct_environment[1] == NULL);

    CHECK(putenv(borrowed_entry) == 0);
    CHECK(environ != direct_environment);
    borrowed = getenv("BORROW");
    CHECK(borrowed == borrowed_entry + 7 && text_equal(borrowed, "first"));
    borrowed_entry[7] = 'F';
    CHECK(text_equal(getenv("BORROW"), "First"));

    CHECK(clearenv() == 0);
    CHECK(aliases_match(NULL));
    /* clearenv must not free or overwrite caller-owned direct storage. */
    CHECK(text_equal(keep, "KEEP=Initial") && text_equal(borrowed_entry,
        "BORROW=First"));
}

static void check_allocation_failure_environment_unchanged(void)
{
    static char base[] = "BASE=before";
    static char *direct_environment[] = { base, NULL };
    static char failure_value[CRABC_FAILURE_VALUE_BYTES];
    pid_t child;

    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        for (size_t index = 0; index + 1 < sizeof(failure_value); ++index)
            failure_value[index] = 'x';
        failure_value[sizeof(failure_value) - 1] = '\0';
        environ = direct_environment;
        CHECK(aliases_match(direct_environment));
        deny_allocation_growth();
        errno = 0;
        CHECK(setenv("BASE", failure_value, 1) == -1 && errno == ENOMEM);
        CHECK(environ == direct_environment &&
            text_equal(direct_environment[0], "BASE=before") &&
            text_equal(getenv("BASE"), "before"));
        _exit(0);
    }
    wait_for_exit(child, 0);
}

static void run_fork_snapshot(void)
{
    int pipefd[2];
    pid_t child;
    char observed = 0;

    CHECK(setenv("FORK_ENV", "parent", 1) == 0);
    CHECK(pipe(pipefd) == 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHECK(close(pipefd[0]) == 0);
        CHECK(text_equal(getenv("FORK_ENV"), "parent"));
        CHECK(setenv("FORK_ENV", "child", 1) == 0);
        CHECK(text_equal(getenv("FORK_ENV"), "child"));
        CHECK(write(pipefd[1], "F", 1) == 1);
        _exit(0);
    }
    CHECK(close(pipefd[1]) == 0);
    CHECK(read(pipefd[0], &observed, 1) == 1 && observed == 'F');
    CHECK(close(pipefd[0]) == 0);
    wait_for_exit(child, 0);
    CHECK(text_equal(getenv("FORK_ENV"), "parent"));
    CHECK(clearenv() == 0);
}

static void run_exec_environment(void)
{
    static char exec_entry[] = "EXEC_ENV=visible";
    static char *exec_environment[] = { exec_entry, NULL };
    char *const arguments[] = { "/consumer", "exec-child", NULL };
    pid_t child;

    CHECK(setenv("PARENT_ENV", "parent", 1) == 0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        execve(arguments[0], arguments, exec_environment);
        _exit(126);
    }
    wait_for_exit(child, 0);
    CHECK(text_equal(getenv("PARENT_ENV"), "parent"));
    CHECK(getenv("EXEC_ENV") == NULL);
    CHECK(clearenv() == 0);
}

static void run_spawn_environment(void)
{
    static char spawn_entry[] = "SPAWN_ENV=visible";
    static char *spawn_environment[] = { spawn_entry, NULL };
    char *const arguments[] = { "/consumer", "spawn-child", NULL };
    pid_t child;

    CHECK(setenv("PARENT_ENV", "parent", 1) == 0);
    CHECK(posix_spawn(&child, arguments[0], NULL, NULL, arguments,
        spawn_environment) == 0);
    wait_for_exit(child, 0);
    CHECK(text_equal(getenv("PARENT_ENV"), "parent"));
    CHECK(getenv("SPAWN_ENV") == NULL);
    CHECK(clearenv() == 0);
}

static void run_exec_child(void)
{
    CHECK(text_equal(getenv("EXEC_ENV"), "visible"));
    CHECK(getenv("PARENT_ENV") == NULL);
    CHECK(environ != NULL && environ[0] != NULL && environ[1] == NULL);
}

static void run_spawn_child(void)
{
    CHECK(text_equal(getenv("SPAWN_ENV"), "visible"));
    CHECK(getenv("PARENT_ENV") == NULL);
    CHECK(environ != NULL && environ[0] != NULL && environ[1] == NULL);
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        if (text_equal(argv[1], "exec-child")) {
            run_exec_child();
            return 0;
        }
        if (text_equal(argv[1], "spawn-child")) {
            run_spawn_child();
            return 0;
        }
        if (text_equal(argv[1], "allocation-failure")) {
            check_allocation_failure_environment_unchanged();
            CHECK(write(1, "environment-allocation-failure-ok\n",
                sizeof("environment-allocation-failure-ok\n") - 1) ==
            (ssize_t)(sizeof("environment-allocation-failure-ok\n") - 1));
            return 0;
        }
        fail();
    }
    CHECK(argc == 1);
    check_replacement_removal_clear();
    check_direct_environ_and_borrowed_value();
    run_fork_snapshot();
    run_exec_environment();
    run_spawn_environment();
    CHECK(write(1, "environment-lifecycle-ok\n",
        sizeof("environment-lifecycle-ok\n") - 1) ==
        (ssize_t)(sizeof("environment-lifecycle-ok\n") - 1));
    return 0;
}
