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
    FIXTURE_EXECVE_STATUS = 41,
    FIXTURE_EXECV_STATUS = 42,
    FIXTURE_EXECLE_STATUS = 43,
    FIXTURE_EXECVP_STATUS = 44,
    FIXTURE_EXECVP_SEARCH_STATUS = 45,
    FIXTURE_FEXECVE_PATH_STATUS = 46,
    FIXTURE_FEXECVE_CLOEXEC_STATUS = 47,
    FIXTURE_EXECVEAT_RELATIVE_STATUS = 48,
    FIXTURE_EXECVEAT_EMPTY_STATUS = 49,
    FIXTURE_EXECVEAT_CLOEXEC_STATUS = 50,
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
    SYS_wait4 == 61 && SYS_exit == 60 && SYS_mmap == 9 && SYS_openat == 257 &&
    SYS_prctl == 157 && SYS_seccomp == 317 && SYS_fcntl == 72,
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
static char inherited_path[] = "PATH=.";
static char inherited_token[] = "CRABC_EXEC_TOKEN=inherited";
static char *inherited_environment[] = {
    inherited_path,
    inherited_token,
    (char *)0,
};
static char searched_after_eacces_path[] =
    "PATH=./process-exec-enoent:./process-exec-eacces:.";
static char *searched_after_eacces_environment[] = {
    searched_after_eacces_path,
    inherited_token,
    (char *)0,
};
static char cwd_only_path[] = "PATH=";
static char *cwd_only_environment[] = {
    cwd_only_path,
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
static char enotdir_last_path[] =
    "PATH=./process-exec-enoent:./process-exec-enotdir";
static char *enotdir_last_environment[] = {
    enotdir_last_path,
    (char *)0,
};
static char enoent_last_path[] =
    "PATH=./process-exec-enotdir:./process-exec-enoent";
static char *enoent_last_environment[] = {
    enoent_last_path,
    (char *)0,
};
static char eacces_last_path[] =
    "PATH=./process-exec-enotdir:./process-exec-eacces";
static char *eacces_last_environment[] = {
    eacces_last_path,
    (char *)0,
};
static char enoexec_after_eacces_path[] =
    "PATH=./process-exec-eacces:./process-exec-enoexec-dir:./process-exec-enoent";
static char *enoexec_after_eacces_environment[] = {
    enoexec_after_eacces_path,
    (char *)0,
};
static char enoexec_before_eacces_path[] =
    "PATH=./process-exec-enoexec-dir:./process-exec-eacces";
static char *enoexec_before_eacces_environment[] = {
    enoexec_before_eacces_path,
    (char *)0,
};
static char searched_explicit_path[] = "PATH=./process-exec-enoent:.";
static char *searched_explicit_environment[] = {
    searched_explicit_path,
    inherited_token,
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

static int write_descriptor_number(char text[16], int descriptor)
{
    char reversed[16];
    unsigned int value = (unsigned int)descriptor;
    size_t length = 0;
    size_t index;

    do {
        if (length == sizeof(reversed) - 1)
            return -1;
        reversed[length++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    for (index = 0; index < length; ++index)
        text[index] = reversed[length - index - 1];
    text[length] = '\0';
    return 0;
}

static long read_descriptor_number(const char *text)
{
    long descriptor = 0;

    if (*text == '\0')
        return -1;
    for (; *text != '\0'; ++text) {
        if (*text < '0' || *text > '9' || descriptor > 214748364)
            return -1;
        descriptor = descriptor * 10 + *text - '0';
    }
    return descriptor;
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
        text_equals(mode, "execvpe-explicit-searched") ||
        text_equals(mode, "fexecve-explicit") ||
        text_equals(mode, "fexecve-path") ||
        text_equals(mode, "fexecve-cloexec") ||
        text_equals(mode, "execveat-relative") ||
        text_equals(mode, "execveat-empty") ||
        text_equals(mode, "execveat-cloexec") ||
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
    if (text_equals(mode, "execvp-after-eacces"))
        return "./process-exec-enoent:./process-exec-eacces:.";
    if (text_equals(mode, "cwd-leading"))
        return ":crabc-missing-leading";
    if (text_equals(mode, "cwd-interior"))
        return "crabc-missing-interior::crabc-after";
    if (text_equals(mode, "cwd-trailing"))
        return "crabc-missing-trailing:";
    if (text_equals(mode, "cwd-only"))
        return "";
    return (const char *)0;
}

static int mode_uses_stack_variadic_arguments(const char *mode)
{
    return text_equals(mode, "execl-inherited") ||
        text_equals(mode, "execle-explicit") ||
        text_equals(mode, "execlp-inherited");
}

static int expected_child_status(const char *mode)
{
    if (text_equals(mode, "execve-explicit"))
        return FIXTURE_EXECVE_STATUS;
    if (text_equals(mode, "execv-inherited"))
        return FIXTURE_EXECV_STATUS;
    if (text_equals(mode, "execle-explicit"))
        return FIXTURE_EXECLE_STATUS;
    if (text_equals(mode, "execvp-inherited"))
        return FIXTURE_EXECVP_STATUS;
    if (text_equals(mode, "execvp-after-eacces"))
        return FIXTURE_EXECVP_SEARCH_STATUS;
    if (text_equals(mode, "fexecve-path"))
        return FIXTURE_FEXECVE_PATH_STATUS;
    if (text_equals(mode, "fexecve-cloexec"))
        return FIXTURE_FEXECVE_CLOEXEC_STATUS;
    if (text_equals(mode, "execveat-relative"))
        return FIXTURE_EXECVEAT_RELATIVE_STATUS;
    if (text_equals(mode, "execveat-empty"))
        return FIXTURE_EXECVEAT_EMPTY_STATUS;
    if (text_equals(mode, "execveat-cloexec"))
        return FIXTURE_EXECVEAT_CLOEXEC_STATUS;
    return 0;
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
    } else if (text_equals(mode, "fexecve-path") ||
        text_equals(mode, "fexecve-cloexec") ||
        text_equals(mode, "execveat-empty") ||
        text_equals(mode, "execveat-cloexec")) {
        long descriptor;
        long flags;

        if (argc != 4 || (descriptor = read_descriptor_number(argv[3])) < 0)
            return 94;
        flags = raw_syscall3(SYS_fcntl, descriptor, F_GETFD, 0);
        if (text_equals(mode, "fexecve-cloexec") ||
            text_equals(mode, "execveat-cloexec")) {
            if (flags != -FIXTURE_EBADF)
                return 98;
        } else if (flags < 0) {
            return 98;
        }
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
    if ((text_equals(mode, "execv-inherited") ||
            text_equals(mode, "execvp-inherited") ||
            text_equals(mode, "execvp-after-eacces") ||
            text_equals(mode, "execlp-inherited")) &&
        !text_equals(environment_value("CRABC_EXEC_TOKEN"), "inherited"))
        return 95;
    if (environment_value("LC_ALL") != (const char *)0)
        return 97;
    if (text_equals(mode, "cwd-only") &&
        environment_value("CRABC_EXEC_TOKEN") != (const char *)0)
        return 96;
    return expected_child_status(mode);
}

static int install_syscall_errno_filter(long syscall_number, int error)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            syscall_number, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | error),
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

static int install_syscall_enosys_filter(long syscall_number)
{
    return install_syscall_errno_filter(syscall_number, FIXTURE_ENOSYS);
}

static int install_execveat_enosys_filter(void)
{
    return install_syscall_enosys_filter(SYS_execveat);
}

static int open_helper(void)
{
    long descriptor = raw_syscall4(SYS_openat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)helper_path, O_RDONLY, 0);

    return descriptor < 0 ? -1 : (int)descriptor;
}

static int open_owned_path(const char *path, int flags)
{
    long descriptor = raw_syscall4(SYS_openat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)path, flags, 0);

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

    environ = inherited_environment;
    (void)execv(self, argv);
    return exec_returned();
}

static int check_execl_success(const char *self)
{
    environ = inherited_environment;
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
    environ = inherited_environment;
    (void)execvp(helper_name, argv);
    return exec_returned();
}

/* Search must continue after both a missing directory entry and EACCES. */
static int check_execvp_after_eacces(const char *self)
{
    char *argv[] = {
        "execvp-after-eacces",
        (char *)child_flag,
        "execvp-after-eacces",
        (char *)0,
    };

    (void)self;
    environ = searched_after_eacces_environment;
    (void)execvp(helper_name, argv);
    return exec_returned();
}

static int check_execlp_success(const char *self)
{
    (void)self;
    environ = inherited_environment;
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

/* The PATH used to find the image is inherited even when envp has a different
 * PATH; the replacement image receives envp and not the search environment. */
static int check_execvpe_searched_explicit_environment(const char *self)
{
    char *argv[] = {
        "execvpe-explicit-searched",
        (char *)child_flag,
        "execvpe-explicit-searched",
        (char *)0,
    };

    (void)self;
    environ = searched_explicit_environment;
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

/* The helper is an owned ELF hard link; each successful replacement validates
 * its own argv and environment before returning a distinct child status. */
static int check_fexecve_path(const char *self)
{
    char *argv[] = { "fexecve-path", (char *)child_flag,
        "fexecve-path", (char *)0, (char *)0 };
    char descriptor_text[16];
    int descriptor = open_owned_path(helper_path, O_PATH);

    (void)self;
    if (descriptor < 0 || write_descriptor_number(descriptor_text, descriptor))
        return 1;
    argv[3] = descriptor_text;
    (void)fexecve(descriptor, argv, explicit_environment);
    return exec_returned();
}

static int check_fexecve_cloexec(const char *self)
{
    char *argv[] = { "fexecve-cloexec", (char *)child_flag,
        "fexecve-cloexec", (char *)0, (char *)0 };
    char descriptor_text[16];
    int descriptor = open_owned_path(helper_path, O_RDONLY | O_CLOEXEC);

    (void)self;
    if (descriptor < 0 || write_descriptor_number(descriptor_text, descriptor))
        return 1;
    argv[3] = descriptor_text;
    (void)fexecve(descriptor, argv, explicit_environment);
    return exec_returned();
}

static int check_execveat_relative(const char *self)
{
    char *argv[] = { "execveat-relative", (char *)child_flag,
        "execveat-relative", (char *)0 };
    int directory = open_owned_path("process-exec-relative",
        O_RDONLY | O_DIRECTORY);

    (void)self;
    if (directory < 0)
        return 1;
    (void)raw_syscall5(SYS_execveat, directory,
        (long)(uintptr_t)"process-exec-helper", (long)(uintptr_t)argv,
        (long)(uintptr_t)explicit_environment, 0);
    return exec_returned();
}

static int check_execveat_empty(const char *self)
{
    char *argv[] = { "execveat-empty", (char *)child_flag,
        "execveat-empty", (char *)0, (char *)0 };
    char descriptor_text[16];
    int descriptor = open_helper();

    (void)self;
    if (descriptor < 0 || write_descriptor_number(descriptor_text, descriptor))
        return 1;
    argv[3] = descriptor_text;
    (void)raw_syscall5(SYS_execveat, descriptor,
        (long)(uintptr_t)"", (long)(uintptr_t)argv,
        (long)(uintptr_t)explicit_environment, FIXTURE_AT_EMPTY_PATH);
    return exec_returned();
}

static int check_execveat_cloexec(const char *self)
{
    char *argv[] = { "execveat-cloexec", (char *)child_flag,
        "execveat-cloexec", (char *)0, (char *)0 };
    char descriptor_text[16];
    int descriptor = open_owned_path(helper_path, O_PATH | O_CLOEXEC);

    (void)self;
    if (descriptor < 0 || write_descriptor_number(descriptor_text, descriptor))
        return 1;
    argv[3] = descriptor_text;
    (void)raw_syscall5(SYS_execveat, descriptor,
        (long)(uintptr_t)"", (long)(uintptr_t)argv,
        (long)(uintptr_t)explicit_environment, FIXTURE_AT_EMPTY_PATH);
    return exec_returned();
}

static int check_execveat_descriptor_errors(const char *self)
{
    char *argv[] = { "execveat-errors", (char *)0 };
    int descriptor = open_helper();

    (void)self;
    if (descriptor < 0)
        return 1;
    if (raw_syscall5(SYS_execveat, -1, (long)(uintptr_t)"",
            (long)(uintptr_t)argv, (long)(uintptr_t)explicit_environment,
            FIXTURE_AT_EMPTY_PATH) != -FIXTURE_EBADF)
        return 2;
    if (raw_syscall5(SYS_execveat, descriptor, (long)(uintptr_t)"",
            (long)(uintptr_t)argv, (long)(uintptr_t)explicit_environment,
            0) != -FIXTURE_ENOENT)
        return 3;
    if (raw_syscall5(SYS_execveat, descriptor,
            (long)(uintptr_t)"process-exec-helper", (long)(uintptr_t)argv,
            (long)(uintptr_t)explicit_environment, 0) != -ENOTDIR)
        return 4;
    if (raw_syscall5(SYS_execveat, descriptor, (long)(uintptr_t)"",
            (long)(uintptr_t)argv, (long)(uintptr_t)explicit_environment,
            FIXTURE_AT_EMPTY_PATH | 0x2000) != -EINVAL)
        return 5;
    return 0;
}

static int check_fexecve_descriptor_errors(const char *self)
{
    char *argv[] = { "fexecve-errors", (char *)0 };
    int directory = open_owned_path("process-exec-relative",
        O_RDONLY | O_DIRECTORY);
    int nonexecutable = open_owned_path(
        "process-exec-eacces/process-exec-eacces-candidate", O_RDONLY);
    int script = open_owned_path("process-exec-script", O_RDONLY | O_CLOEXEC);

    (void)self;
    if (directory < 0 || nonexecutable < 0 || script < 0)
        return 1;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (fexecve(directory, argv, explicit_environment) != -1 ||
        errno != FIXTURE_EACCES)
        return 2;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (fexecve(nonexecutable, argv, explicit_environment) != -1 ||
        errno != FIXTURE_EACCES)
        return 3;
    /* The script's interpreter is owned by this fixture; the kernel still
     * needs the script descriptor after exec and CLOEXEC makes it unavailable. */
    errno = FIXTURE_ERRNO_SENTINEL;
    if (fexecve(script, argv, explicit_environment) != -1 ||
        errno != FIXTURE_ENOENT)
        return 4;
    return 0;
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

static int check_empty_path_whole(const char *self)
{
    (void)self;
    return check_empty_path_component(cwd_only_environment, "cwd-only");
}

static int check_default_path(const char *self)
{
    char *argv[] = {
        "true",
        (char *)0,
    };

    (void)self;
    environ = empty_environment;
    /* All search attempts receive ENOENT without executing a host image. */
    if (install_syscall_errno_filter(SYS_execve, FIXTURE_ENOENT) != 0)
        return 1;
    errno = FIXTURE_ERRNO_SENTINEL;
    return execvp("true", argv) == -1 && errno == FIXTURE_ENOENT ? 0 : 2;
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

static int check_search_errno(char **search_environment, int expected,
    int explicit_envp)
{
    char *argv[] = {
        "process-exec-eacces-candidate",
        (char *)0,
    };
    int result;

    environ = search_environment;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (explicit_envp)
        result = execvpe("process-exec-eacces-candidate", argv,
            explicit_environment);
    else
        result = execvp("process-exec-eacces-candidate", argv);
    return result == -1 && errno == expected ? 0 : 1;
}

/* Without EACCES, the last attempted component's ENOTDIR or ENOENT wins. */
static int check_enotdir_last(const char *self)
{
    (void)self;
    return check_search_errno(enotdir_last_environment, ENOTDIR, 0);
}

static int check_enoent_last(const char *self)
{
    (void)self;
    return check_search_errno(enoent_last_environment, ENOENT, 0);
}

/* EACCES wins regardless of its position and envp cannot redirect search. */
static int check_eacces_last_explicit_environment(const char *self)
{
    (void)self;
    return check_search_errno(eacces_last_environment, EACCES, 1);
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

static int check_enoexec_before_eacces_is_terminal(const char *self)
{
    char *argv[] = {
        "process-exec-eacces-candidate",
        (char *)0,
    };

    (void)self;
    environ = enoexec_before_eacces_environment;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execvpe("process-exec-eacces-candidate", argv,
            explicit_environment) != -1 || errno != FIXTURE_ENOEXEC)
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

/* A short execlp argument list must reach PATH search even when anonymous
 * mappings are unavailable. Musl builds this vector on the caller's stack. */
static int check_execlp_without_mmap(const char *self)
{
    (void)self;
    environ = slash_bypass_environment;
    if (install_syscall_enosys_filter(SYS_mmap) != 0)
        return 1;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execlp("process-exec-mmap-filter-missing", "missing", "stack-word-one",
            "stack-word-two", "stack-word-three", "stack-word-four",
            (char *)0) != -1 || errno != FIXTURE_ENOENT)
        return 2;
    return 0;
}

/* A larger finite variadic list still reaches the same PATH result. */
static int check_execlp_large_argv(const char *self)
{
    (void)self;
    environ = slash_bypass_environment;
    errno = FIXTURE_ERRNO_SENTINEL;
    if (execlp("process-exec-large-argv-missing", "missing",
            "one", "two", "three", "four", "five", "six", "seven",
            "eight", "nine", "ten", "eleven", "twelve", "thirteen",
            "fourteen", "fifteen", "sixteen", (char *)0) != -1 ||
        errno != FIXTURE_ENOENT)
        return 1;
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

struct check_case {
    const char *name;
    isolated_check check;
    int expected_exit;
};

/* Raw wait status keeps exit and signal failures distinct in both streams. */
static int trace_case(const char *name, int status)
{
    char line[96];
    char digits[16];
    size_t length = 0;
    size_t digit_count = 0;
    unsigned int value;

    while (*name != '\0' && length < sizeof(line) - 18)
        line[length++] = *name++;
    line[length++] = ' ';
    if (status < 0) {
        line[length++] = '-';
        value = (unsigned int)(-status);
    } else {
        value = (unsigned int)status;
    }
    do {
        digits[digit_count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (digit_count != 0)
        line[length++] = digits[--digit_count];
    line[length++] = '\n';
    return raw_syscall3(SYS_write, 1, (long)(uintptr_t)line, length) ==
        (long)length ? 0 : -1;
}

static int run_isolated(const char *self, isolated_check check)
{
    long child = raw_syscall0(SYS_fork);
    int status = 0;
    long waited;

    if (child < 0)
        return -1;
    if (child == 0)
        raw_exit(check(self));
    do {
        waited = raw_syscall4(SYS_wait4, child, (long)(uintptr_t)&status, 0, 0);
    } while (waited == -FIXTURE_EINTR);
    return waited == child ? status : -1;
}

static int run_parent(const char *self)
{
    static const struct check_case checks[] = {
        { "direct-failure-errno", check_direct_failure_errno, 0 },
        { "execve-explicit", check_execve_success, FIXTURE_EXECVE_STATUS },
        { "execv-inherited", check_execv_success, FIXTURE_EXECV_STATUS },
        { "execl-inherited", check_execl_success, 0 },
        { "execle-explicit", check_execle_success, FIXTURE_EXECLE_STATUS },
        { "execvp-inherited", check_execvp_success, FIXTURE_EXECVP_STATUS },
        { "execvp-after-eacces", check_execvp_after_eacces,
            FIXTURE_EXECVP_SEARCH_STATUS },
        { "execlp-inherited", check_execlp_success, 0 },
        { "execvpe-explicit", check_execvpe_success, 0 },
        { "execvpe-search-env", check_execvpe_searched_explicit_environment, 0 },
        { "empty-path-leading", check_empty_path_leading, 0 },
        { "empty-path-interior", check_empty_path_interior, 0 },
        { "empty-path-trailing", check_empty_path_trailing, 0 },
        { "empty-path-whole", check_empty_path_whole, 0 },
        { "default-path", check_default_path, 0 },
        { "enoexec-terminal", check_enoexec_is_terminal, 0 },
        { "eacces-precedence", check_eacces_precedence, 0 },
        { "enotdir-last", check_enotdir_last, 0 },
        { "enoent-last", check_enoent_last, 0 },
        { "eacces-last-explicit-env", check_eacces_last_explicit_environment, 0 },
        { "enoexec-after-eacces", check_enoexec_after_eacces_is_terminal, 0 },
        { "enoexec-before-eacces", check_enoexec_before_eacces_is_terminal, 0 },
        { "name-bounds-slash", check_path_name_bounds_and_slash_bypass, 0 },
        { "execlp-no-mmap", check_execlp_without_mmap, 0 },
        { "execlp-large-argv", check_execlp_large_argv, 0 },
        { "fexecve-explicit", check_fexecve_success, 0 },
        { "fexecve-path", check_fexecve_path, FIXTURE_FEXECVE_PATH_STATUS },
        { "fexecve-cloexec", check_fexecve_cloexec,
            FIXTURE_FEXECVE_CLOEXEC_STATUS },
        { "execveat-relative", check_execveat_relative,
            FIXTURE_EXECVEAT_RELATIVE_STATUS },
        { "execveat-empty", check_execveat_empty,
            FIXTURE_EXECVEAT_EMPTY_STATUS },
        { "execveat-cloexec", check_execveat_cloexec,
            FIXTURE_EXECVEAT_CLOEXEC_STATUS },
        { "execveat-descriptor-errors", check_execveat_descriptor_errors, 0 },
        { "fexecve-descriptor-errors", check_fexecve_descriptor_errors, 0 },
        { "fexecve-enosys", check_fexecve_enosys, 0 },
    };
    size_t index;

    for (index = 0; index < sizeof(checks) / sizeof(checks[0]); ++index) {
        int status = run_isolated(self, checks[index].check);

        if (trace_case(checks[index].name, status) != 0)
            return (int)(index + 1);
        if (status != checks[index].expected_exit << 8)
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
