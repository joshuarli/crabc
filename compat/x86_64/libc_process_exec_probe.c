/* Native Linux/x86-64 direct process-exec C ABI differential.
 *
 * The parent never replaces its own image. Every successful exec happens in a
 * raw-forked child which enters this same fixture's --crabc-exec-child mode.
 * The runner first links this source against pinned musl 1.2.6, then links
 * its opt-in public exec surface ahead of musl. The test deliberately keeps
 * child control fixture-local: it selects neither fork/vfork/clone nor a
 * process-supervision API.
 *
 * Pinned musl's execvpe search treats every empty PATH component as the
 * current directory and returns ENOEXEC rather than invoking a shell. The
 * fexecve seccomp case records the project Linux-5.10 exception separately:
 * musl's historic ENOSYS procfd fallback succeeds, while the candidate must
 * return ENOSYS directly without a procfd attempt.
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
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    FIXTURE_E2BIG = 7,
    FIXTURE_EINTR = 4,
    FIXTURE_EBADF = 9,
    FIXTURE_EACCES = 13,
    FIXTURE_ENOENT = 2,
    FIXTURE_ENOEXEC = 8,
    FIXTURE_ENOSYS = 38,
    FIXTURE_ENAMETOOLONG = 36,
    FIXTURE_ERRNO_SENTINEL = 34,
    FIXTURE_AT_FDCWD = -100,
    FIXTURE_AT_EMPTY_PATH = 0x1000,
};

struct crabc_bpf_instruction {
    uint16_t code;
    uint8_t jump_true;
    uint8_t jump_false;
    uint32_t immediate;
};

struct crabc_bpf_program {
    uint16_t length;
    struct crabc_bpf_instruction *instructions;
};

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
};

#define CRABC_BPF_STATEMENT(instruction_code, value) \
    { (uint16_t)(instruction_code), 0, 0, (uint32_t)(value) }
#define CRABC_BPF_JUMP(instruction_code, value, yes, no) \
    { (uint16_t)(instruction_code), (uint8_t)(yes), (uint8_t)(no), \
      (uint32_t)(value) }

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86-64 LP64 words");
_Static_assert(SYS_execve == 59 && SYS_execveat == 322 && SYS_fork == 57 &&
    SYS_wait4 == 61 && SYS_exit == 60 && SYS_openat == 257 &&
    SYS_prctl == 157 && SYS_seccomp == 317,
    "Linux x86-64 process-exec and fixture syscall numbers");
_Static_assert(E2BIG == FIXTURE_E2BIG && ENOENT == FIXTURE_ENOENT &&
    ENOEXEC == FIXTURE_ENOEXEC && ENOSYS == FIXTURE_ENOSYS &&
    ENAMETOOLONG == FIXTURE_ENAMETOOLONG && EACCES == FIXTURE_EACCES &&
    EBADF == FIXTURE_EBADF,
    "Linux process-exec errno values");
_Static_assert(AT_FDCWD == FIXTURE_AT_FDCWD, "x86 AT_FDCWD");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execve),
    int (*)(const char *, char *const [], char *const [])),
    "execve declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execvpe),
    int (*)(const char *, char *const [], char *const [])),
    "execvpe declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fexecve),
    int (*)(int, char *const [], char *const [])),
    "fexecve declaration");

#if defined(CRABC_PROCESS_EXEC_EXECVE_ONLY)

/* A normal static consumer for the runner's no-ambient-closure link audit. */
int main(void)
{
    char *argv[] = {
        "execve-only",
        (char *)0,
    };
    char *environment[] = {
        (char *)0,
    };

    errno = FIXTURE_ERRNO_SENTINEL;
    return execve("./crabc-process-exec-missing", argv, environment) == -1 &&
        errno == FIXTURE_ENOENT ? 0 : 1;
}

#elif defined(CRABC_PROCESS_EXEC_FEXECVE_ONLY)

/* fexecve-only must not incidentally need PATH or variadic-argv machinery. */
int main(void)
{
    char *argv[] = {
        "fexecve-only",
        (char *)0,
    };
    char *environment[] = {
        (char *)0,
    };

    errno = FIXTURE_ERRNO_SENTINEL;
    return fexecve(-1, argv, environment) == -1 && errno == FIXTURE_EBADF ?
        0 : 1;
}

#elif defined(CRABC_PROCESS_EXEC_STRONG_OVERRIDE)

/* A consumer's strong public execvpe must override only the weak alias. */
int execvpe(const char *file, char *const argv[], char *const environment[])
{
    (void)file;
    (void)argv;
    (void)environment;
    errno = FIXTURE_E2BIG;
    return 73;
}

int main(void)
{
    char *argv[] = {
        "strong-execvpe-override",
        (char *)0,
    };
    char *environment[] = {
        (char *)0,
    };

    errno = FIXTURE_ERRNO_SENTINEL;
    if (execvpe("strong-override", argv, environment) != 73 ||
        errno != FIXTURE_E2BIG)
        return 1;
    /* execvp must retain its internal __execvpe path, not use this override. */
    errno = FIXTURE_ERRNO_SENTINEL;
    return execvp("./crabc-process-exec-missing", argv) == -1 &&
        errno == FIXTURE_ENOENT ? 0 : 2;
}

#else

static const char child_flag[] = "--crabc-exec-child";
static const char helper_name[] = "process-exec-helper";
static const char enoexec_name[] = "process-exec-enoexec";
static const char missing_path[] = "./crabc-process-exec-missing";
static const char helper_path[] = "./process-exec-helper";
static const char slash_bypass_path[] =
    "./process-exec-eacces/process-exec-eacces-candidate";

static char explicit_path[] = "PATH=/crabc-explicit-path-must-not-search";
static char explicit_token[] = "CRABC_EXEC_TOKEN=explicit";
static char *explicit_environment[] = {
    explicit_path,
    explicit_token,
    (char *)0,
};
static char *empty_environment[] = {
    (char *)0,
};
static char cwd_leading_path[] = "PATH=:crabc-missing-leading";
static char *cwd_leading_environment[] = {
    cwd_leading_path,
    (char *)0,
};
static char cwd_interior_path[] = "PATH=crabc-missing-interior::crabc-after";
static char *cwd_interior_environment[] = {
    cwd_interior_path,
    (char *)0,
};
static char cwd_trailing_path[] = "PATH=crabc-missing-trailing:";
static char *cwd_trailing_environment[] = {
    cwd_trailing_path,
    (char *)0,
};
static char eacces_precedence_path[] =
    "PATH=./process-exec-eacces:./process-exec-enoent:./process-exec-enotdir";
static char *eacces_precedence_environment[] = {
    eacces_precedence_path,
    (char *)0,
};
static char enoexec_after_eacces_path[] =
    "PATH=./process-exec-eacces:./process-exec-enoexec-dir:./process-exec-enoent";
static char *enoexec_after_eacces_environment[] = {
    enoexec_after_eacces_path,
    (char *)0,
};
static char slash_bypass_search_path[] = "PATH=./process-exec-enoent";
static char *slash_bypass_environment[] = {
    slash_bypass_search_path,
    (char *)0,
};

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall5(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5)
        : "rcx", "r11", "memory");
    return result;
}

__attribute__((noreturn)) static void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    for (;;)
        ;
}

static int text_equals(const char *left, const char *right)
{
    size_t index = 0;

    for (;;) {
        if (left[index] != right[index])
            return 0;
        if (left[index] == '\0')
            return 1;
        ++index;
    }
}

static const char *environment_value(const char *name)
{
    size_t name_length = 0;
    char **cursor;

    while (name[name_length] != '\0')
        ++name_length;
    for (cursor = environ; cursor != (char **)0 && *cursor != (char *)0;
         ++cursor) {
        size_t index = 0;

        while (index != name_length && (*cursor)[index] == name[index])
            ++index;
        if (index == name_length && (*cursor)[index] == '=')
            return *cursor + name_length + 1;
    }
    return (const char *)0;
}

static int mode_requires_explicit_environment(const char *mode)
{
    return text_equals(mode, "execve-explicit") ||
        text_equals(mode, "execle-explicit") ||
        text_equals(mode, "execvpe-explicit") ||
        text_equals(mode, "fexecve-explicit") ||
        text_equals(mode, "fexecve-enosys-musl-procfd");
}

static const char *expected_path_for_mode(const char *mode)
{
    if (mode_requires_explicit_environment(mode))
        return "/crabc-explicit-path-must-not-search";
    if (text_equals(mode, "execv-inherited") ||
        text_equals(mode, "execl-inherited") ||
        text_equals(mode, "execvp-inherited") ||
        text_equals(mode, "execlp-inherited"))
        return ".";
    if (text_equals(mode, "cwd-leading"))
        return ":crabc-missing-leading";
    if (text_equals(mode, "cwd-interior"))
        return "crabc-missing-interior::crabc-after";
    if (text_equals(mode, "cwd-trailing"))
        return "crabc-missing-trailing:";
    return (const char *)0;
}

static int mode_uses_stack_variadic_arguments(const char *mode)
{
    return text_equals(mode, "execl-inherited") ||
        text_equals(mode, "execle-explicit") ||
        text_equals(mode, "execlp-inherited");
}

static int check_exec_child(int argc, char **argv)
{
    const char *mode;
    const char *expected_path;

    if (argc < 3 || !text_equals(argv[1], child_flag) ||
        !text_equals(argv[0], argv[2]))
        return 90;
    mode = argv[2];
    if (mode_uses_stack_variadic_arguments(mode)) {
        if (argc != 7 || !text_equals(argv[3], "stack-word-one") ||
            !text_equals(argv[4], "stack-word-two") ||
            !text_equals(argv[5], "stack-word-three") ||
            !text_equals(argv[6], "stack-word-four"))
            return 94;
    } else if (argc != 3) {
        return 94;
    }
    expected_path = expected_path_for_mode(mode);
    if (expected_path == (const char *)0)
        return 91;
    if (!text_equals(environment_value("PATH"), expected_path))
        return 92;
    if (mode_requires_explicit_environment(mode) &&
        !text_equals(environment_value("CRABC_EXEC_TOKEN"), "explicit"))
        return 93;
    return 0;
}

static int install_execveat_enosys_filter(void)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_execveat, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | FIXTURE_ENOSYS),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ALLOW),
    };
    struct crabc_bpf_program program = {
        .length = (uint16_t)(sizeof(filter) / sizeof(filter[0])),
        .instructions = filter,
    };

    if (raw_syscall5(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    if (raw_syscall3(SYS_seccomp, CRABC_SECCOMP_SET_MODE_FILTER, 0,
            (long)(uintptr_t)&program) != 0)
        return -1;
    return 0;
}

static int open_helper(void)
{
    long descriptor = raw_syscall4(SYS_openat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)helper_path, O_RDONLY, 0);

    return descriptor < 0 ? -1 : (int)descriptor;
}

static int exec_returned(void)
{
    return 1;
}

static int check_execve_success(const char *self)
{
    char *argv[] = {
        "execve-explicit",
        (char *)child_flag,
        "execve-explicit",
        (char *)0,
    };

    (void)execve(self, argv, explicit_environment);
    return exec_returned();
}

static int check_execv_success(const char *self)
{
    char *argv[] = {
        "execv-inherited",
        (char *)child_flag,
        "execv-inherited",
        (char *)0,
    };

    (void)execv(self, argv);
    return exec_returned();
}

static int check_execl_success(const char *self)
{
    (void)execl(self, "execl-inherited", child_flag, "execl-inherited",
        "stack-word-one", "stack-word-two", "stack-word-three",
        "stack-word-four", (char *)0);
    return exec_returned();
}

static int check_execle_success(const char *self)
{
    (void)execle(self, "execle-explicit", child_flag, "execle-explicit",
        "stack-word-one", "stack-word-two", "stack-word-three",
        "stack-word-four", (char *)0, explicit_environment);
    return exec_returned();
}

static int check_execvp_success(const char *self)
{
    char *argv[] = {
        "execvp-inherited",
        (char *)child_flag,
        "execvp-inherited",
        (char *)0,
    };

    (void)self;
    (void)execvp(helper_name, argv);
    return exec_returned();
}

static int check_execlp_success(const char *self)
{
    (void)self;
    (void)execlp(helper_name, "execlp-inherited", child_flag,
        "execlp-inherited", "stack-word-one", "stack-word-two",
        "stack-word-three", "stack-word-four", (char *)0);
    return exec_returned();
}

static int check_execvpe_success(const char *self)
{
    char *argv[] = {
        "execvpe-explicit",
        (char *)child_flag,
        "execvpe-explicit",
        (char *)0,
    };

    (void)self;
    (void)execvpe(helper_name, argv, explicit_environment);
    return exec_returned();
}

static int check_fexecve_success(const char *self)
{
    char *argv[] = {
        "fexecve-explicit",
        (char *)child_flag,
        "fexecve-explicit",
        (char *)0,
    };
    int descriptor = open_helper();

    (void)self;
    if (descriptor < 0)
        return 1;
    (void)fexecve(descriptor, argv, explicit_environment);
    return exec_returned();
}

static int check_empty_path_component(char **environment, const char *mode)
{
    char *argv[] = {
        (char *)mode,
        (char *)child_flag,
        (char *)mode,
        (char *)0,
    };

    environ = environment;
    (void)execvp(helper_name, argv);
    return exec_returned();
}

static int check_empty_path_leading(const char *self)
{
    (void)self;
    return check_empty_path_component(cwd_leading_environment, "cwd-leading");
}

static int check_empty_path_interior(const char *self)
{
    (void)self;
    return check_empty_path_component(cwd_interior_environment, "cwd-interior");
}

static int check_empty_path_trailing(const char *self)
{
    (void)self;
    return check_empty_path_component(cwd_trailing_environment, "cwd-trailing");
}

static int check_default_path(const char *self)
{
    char *argv[] = {
        "true",
        (char *)0,
    };

    (void)self;
    environ = empty_environment;
    (void)execvp("true", argv);
    return exec_returned();
}

static int check_enoexec_is_terminal(const char *self)
{
    char *argv[] = {
        "process-exec-enoexec",
        (char *)child_flag,
        "enoexec-must-not-shell-fallback",
        (char *)0,
    };

    (void)self;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execvp(enoexec_name, argv) != -1 || errno != FIXTURE_ENOEXEC)
        return 1;
    return 0;
}

/* EACCES from one searched component wins over later ENOENT and ENOTDIR. */
static int check_eacces_precedence(const char *self)
{
    char *argv[] = {
        "process-exec-eacces-candidate",
        (char *)0,
    };

    (void)self;
    environ = eacces_precedence_environment;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execvp("process-exec-eacces-candidate", argv) != -1 ||
        errno != FIXTURE_EACCES)
        return 1;
    return 0;
}

/* A later ENOEXEC remains terminal even after an earlier EACCES candidate. */
static int check_enoexec_after_eacces_is_terminal(const char *self)
{
    char *argv[] = {
        "process-exec-eacces-candidate",
        (char *)child_flag,
        "enoexec-after-eacces-must-not-shell-fallback",
        (char *)0,
    };

    (void)self;
    environ = enoexec_after_eacces_environment;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execvp("process-exec-eacces-candidate", argv) != -1 ||
        errno != FIXTURE_ENOEXEC)
        return 1;
    return 0;
}

/* Bare names have NAME_MAX preflight; slash paths bypass PATH construction. */
static int check_path_name_bounds_and_slash_bypass(const char *self)
{
    char bare_name[257];
    char *argv[] = {
        bare_name,
        (char *)0,
    };
    size_t index;

    for (index = 0; index != sizeof(bare_name) - 1; ++index)
        bare_name[index] = 'n';
    bare_name[sizeof(bare_name) - 1] = '\0';
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execvp(bare_name, argv) != -1 || errno != FIXTURE_ENAMETOOLONG)
        return 1;

    /* The selected PATH would yield ENOENT; a slash must reach EACCES directly. */
    argv[0] = (char *)slash_bypass_path;
    environ = slash_bypass_environment;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execvp(slash_bypass_path, argv) != -1 || errno != FIXTURE_EACCES)
        return 2;
    (void)self;
    return 0;
}

static int check_direct_failure_errno(const char *self)
{
    char *argv[] = {
        "process-exec-missing",
        (char *)0,
    };

    errno = FIXTURE_ERRNO_SENTINEL;
    if (execve(missing_path, argv, explicit_environment) != -1 ||
        errno != FIXTURE_ENOENT)
        return 1;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execv(missing_path, argv) != -1 || errno != FIXTURE_ENOENT)
        return 2;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execl(missing_path, "process-exec-missing", (char *)0) != -1 ||
        errno != FIXTURE_ENOENT)
        return 3;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execle(missing_path, "process-exec-missing", (char *)0,
            explicit_environment) != -1 || errno != FIXTURE_ENOENT)
        return 4;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execvp(missing_path, argv) != -1 || errno != FIXTURE_ENOENT)
        return 5;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execlp(missing_path, "process-exec-missing", (char *)0) != -1 ||
        errno != FIXTURE_ENOENT)
        return 6;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execvpe(missing_path, argv, explicit_environment) != -1 ||
        errno != FIXTURE_ENOENT)
        return 7;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (fexecve(-1, argv, explicit_environment) != -1 ||
        errno != FIXTURE_EBADF)
        return 8;
    (void)self;
    return 0;
}

static int check_fexecve_enosys(const char *self)
{
    char *argv[] = {
#if defined(CRABC_PROCESS_EXEC_CANDIDATE)
        "fexecve-enosys-must-not-exec",
#else
        "fexecve-enosys-musl-procfd",
#endif
        (char *)child_flag,
#if defined(CRABC_PROCESS_EXEC_CANDIDATE)
        "fexecve-enosys-must-not-exec",
#else
        "fexecve-enosys-musl-procfd",
#endif
        (char *)0,
    };
    int descriptor = open_helper();

    (void)self;
    if (descriptor < 0 || install_execveat_enosys_filter() != 0)
        return 1;
#if defined(CRABC_PROCESS_EXEC_CANDIDATE)
    errno = FIXTURE_ERRNO_SENTINEL;
    if (fexecve(descriptor, argv, explicit_environment) != -1 ||
        errno != FIXTURE_ENOSYS)
        return 2;
    return 0;
#else
    (void)fexecve(descriptor, argv, explicit_environment);
    return exec_returned();
#endif
}

typedef int (*isolated_check)(const char *);

static int run_isolated(const char *self, isolated_check check)
{
    long child = raw_syscall0(SYS_fork);
    int status = 0;
    long waited;

    if (child < 0)
        return -1;
    if (child == 0)
        raw_exit(check(self) == 0 ? 0 : 127);
    do {
        waited = raw_syscall4(SYS_wait4, child, (long)(uintptr_t)&status, 0, 0);
    } while (waited == -FIXTURE_EINTR);
    return waited == child && status == 0 ? 0 : -1;
}

static int run_parent(const char *self)
{
    static isolated_check const checks[] = {
        check_direct_failure_errno,
        check_execve_success,
        check_execv_success,
        check_execl_success,
        check_execle_success,
        check_execvp_success,
        check_execlp_success,
        check_execvpe_success,
        check_empty_path_leading,
        check_empty_path_interior,
        check_empty_path_trailing,
        check_default_path,
        check_enoexec_is_terminal,
        check_eacces_precedence,
        check_enoexec_after_eacces_is_terminal,
        check_path_name_bounds_and_slash_bypass,
        check_fexecve_success,
        check_fexecve_enosys,
    };
    size_t index;

    for (index = 0; index < sizeof(checks) / sizeof(checks[0]); ++index) {
        if (run_isolated(self, checks[index]) != 0)
            return (int)(index + 1);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 3 && text_equals(argv[1], child_flag))
        return check_exec_child(argc, argv);
    if (argc != 1)
        return 99;
    return run_parent(argv[0]);
}

#endif
