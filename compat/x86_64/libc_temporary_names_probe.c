/* Native Linux/x86-64 legacy tmpnam/tempnam C ABI regression.
 *
 * The same GNU-enabled project-header fixture first executes against pinned
 * musl 1.2.6 and then against the opt-in crabc archive.  It records only
 * musl's historical pathname-generation contract: neither entry creates,
 * opens, reserves, nor unlinks the returned pathname.  The runner supplies a
 * deliberately unusable TMPDIR value, so the fixed /tmp defaults remain
 * observable without treating these racy names as safe temporary files.
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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

enum {
    FIXTURE_ENOENT = 2,
    FIXTURE_ENAMETOOLONG = 36,
    FIXTURE_ELOOP = 40,
    FIXTURE_PATH_MAX = 4096,
    FIXTURE_UNCHANGED_ERRNO = 34,
};

/* This fixture-only classic-BPF program makes raw readlink failure
 * deterministic after the normal musl comparison. It neither selects a
 * public seccomp interface nor filters any syscall other than readlink. */
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

_Static_assert(sizeof(size_t) == 8 && sizeof(void *) == 8,
    "x86-64 LP64 widths");
_Static_assert(SYS_readlink == 89 && SYS_clock_gettime == 228 &&
    SYS_gettid == 186 && SYS_prctl == 157 && SYS_seccomp == 317,
    "Linux x86-64 temporary-name and fixture syscall numbers");
_Static_assert(L_tmpnam == 20, "musl tmpnam static buffer extent");
_Static_assert(ENOENT == FIXTURE_ENOENT && ENAMETOOLONG == FIXTURE_ENAMETOOLONG &&
    ELOOP == FIXTURE_ELOOP, "Linux temporary-name errno values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tmpnam),
    char *(*)(char *)), "tmpnam declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&tempnam),
    char *(*)(const char *, const char *)), "tempnam declaration");

#ifdef CRABC_TEMPORARY_NAMES_CANDIDATE
extern size_t __crabc_x86_temporary_names_v1(void);
#endif

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

static int install_readlink_failure_filter(void)
{
    struct crabc_bpf_instruction filter[] = {
        CRABC_BPF_STATEMENT(CRABC_BPF_LD | CRABC_BPF_W | CRABC_BPF_ABS, 0),
        CRABC_BPF_JUMP(CRABC_BPF_JMP | CRABC_BPF_JEQ | CRABC_BPF_K,
            SYS_readlink, 0, 1),
        CRABC_BPF_STATEMENT(CRABC_BPF_RET | CRABC_BPF_K,
            CRABC_SECCOMP_RET_ERRNO | FIXTURE_ELOOP),
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

static size_t text_length(const char *text)
{
    size_t length = 0;

    while (text[length] != '\0')
        ++length;
    return length;
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

static int has_prefix(const char *text, const char *prefix)
{
    size_t index = 0;

    while (prefix[index] != '\0') {
        if (text[index] != prefix[index])
            return 0;
        ++index;
    }
    return 1;
}

static int has_musl_randname_suffix(const char *path)
{
    size_t length = text_length(path);
    size_t index;

    if (length < 6)
        return 0;
    for (index = length - 6; index < length; ++index) {
        if (!((path[index] >= 'A' && path[index] <= 'P') ||
            (path[index] >= 'a' && path[index] <= 'p')))
            return 0;
    }
    return 1;
}

static int path_is_absent(const char *path)
{
    char output;

    /* tmpnam/tempnam use raw readlink with this one-byte output extent. */
    return raw_syscall3(SYS_readlink, (long)(uintptr_t)path,
        (long)(uintptr_t)&output, 1) == -FIXTURE_ENOENT;
}

static int has_generated_path(const char *path, const char *prefix)
{
    return has_prefix(path, prefix) && has_musl_randname_suffix(path) &&
        path_is_absent(path);
}

/* Build a PATH_MAX-1 directory spelling whose first non-/tmp component is
 * an immediately preceding absent tmpnam result. Subsequent components stay
 * below NAME_MAX, so raw readlink reaches that known absent component instead
 * of rejecting an overlong individual path component before tempnam can
 * observe musl's total-PATH_MAX boundary. */
static int build_path_max_minus_one_directory(char *directory)
{
    char absent_root[L_tmpnam];
    size_t length = 0;

    if (tmpnam(absent_root) != absent_root ||
        !has_generated_path(absent_root, "/tmp/tmpnam_"))
        return -1;
    while (absent_root[length] != '\0') {
        directory[length] = absent_root[length];
        ++length;
    }
    while (length < FIXTURE_PATH_MAX - 9) {
        size_t component_length = 0;

        directory[length++] = '/';
        while (length < FIXTURE_PATH_MAX - 9 && component_length != 200) {
            directory[length++] = 'p';
            ++component_length;
        }
    }
    directory[length] = '\0';
    return 0;
}

static int check_tmpnam(void)
{
    char caller[L_tmpnam];
    char *internal;
    char *next_internal;

    caller[L_tmpnam - 1] = '!';
    errno = FIXTURE_UNCHANGED_ERRNO;
    if (tmpnam(caller) != caller ||
        !has_generated_path(caller, "/tmp/tmpnam_") ||
        text_length(caller) != 18 || caller[L_tmpnam - 1] != '!' ||
        errno != FIXTURE_UNCHANGED_ERRNO)
        return 1;

    errno = FIXTURE_UNCHANGED_ERRNO;
    internal = tmpnam((char *)0);
    if (internal == (char *)0 || internal == caller ||
        !has_generated_path(internal, "/tmp/tmpnam_") ||
        text_length(internal) != 18 || errno != FIXTURE_UNCHANGED_ERRNO)
        return 2;

    errno = FIXTURE_UNCHANGED_ERRNO;
    next_internal = tmpnam((char *)0);
    if (next_internal != internal ||
        !has_generated_path(next_internal, "/tmp/tmpnam_") ||
        text_length(next_internal) != 18 || errno != FIXTURE_UNCHANGED_ERRNO)
        return 3;
    return 0;
}

static int check_tempnam(void)
{
    char long_directory[FIXTURE_PATH_MAX];
    char long_prefix[FIXTURE_PATH_MAX];
    char *name;
    size_t index;

    if (!text_equals(P_tmpdir, "/tmp"))
        return 1;

    /* The runner's TMPDIR must not affect source-selected NULL defaults. */
    errno = FIXTURE_UNCHANGED_ERRNO;
    name = tempnam((const char *)0, (const char *)0);
    if (name == (char *)0 || !has_generated_path(name, "/tmp/temp_") ||
        text_length(name) != 16 || errno != FIXTURE_UNCHANGED_ERRNO)
        return 2;
    free(name);
    if (errno != FIXTURE_UNCHANGED_ERRNO)
        return 3;

    errno = FIXTURE_UNCHANGED_ERRNO;
    name = tempnam("/tmp/", "named");
    if (name == (char *)0 || !has_generated_path(name, "/tmp//named_") ||
        text_length(name) != 18 || errno != FIXTURE_UNCHANGED_ERRNO)
        return 4;
    free(name);
    if (errno != FIXTURE_UNCHANGED_ERRNO)
        return 5;

    /* Empty inputs remain empty; musl still inserts its one separating slash. */
    errno = FIXTURE_UNCHANGED_ERRNO;
    name = tempnam("", "");
    if (name == (char *)0 || !has_generated_path(name, "/_") ||
        text_length(name) != 8 || errno != FIXTURE_UNCHANGED_ERRNO)
        return 6;
    free(name);
    if (errno != FIXTURE_UNCHANGED_ERRNO)
        return 7;

    errno = FIXTURE_UNCHANGED_ERRNO;
    if (build_path_max_minus_one_directory(long_directory) != 0)
        return 8;
    errno = FIXTURE_UNCHANGED_ERRNO;
    name = tempnam(long_directory, "");
    if (name == (char *)0 || !has_generated_path(name, long_directory) ||
        text_length(name) != FIXTURE_PATH_MAX - 1 ||
        errno != FIXTURE_UNCHANGED_ERRNO)
        return 9;
    free(name);
    if (errno != FIXTURE_UNCHANGED_ERRNO)
        return 10;

    /* /tmp plus a 4084-byte prefix makes musl's l exactly PATH_MAX. */
    for (index = 0; index < FIXTURE_PATH_MAX - 12; ++index)
        long_prefix[index] = 'p';
    long_prefix[FIXTURE_PATH_MAX - 12] = '\0';
    errno = 0;
    name = tempnam("/tmp", long_prefix);
    if (name != (char *)0 || errno != FIXTURE_ENAMETOOLONG)
        return 11;

    /* A non-directory path component makes raw readlink return -ENOTDIR.
     * Musl retries but neither treats that as absence nor translates errno. */
    errno = FIXTURE_UNCHANGED_ERRNO;
    name = tempnam("/dev/null", "x");
    if (name != (char *)0 || errno != FIXTURE_UNCHANGED_ERRNO)
        return 12;
    return 0;
}

static int check_readlink_failure_retry(void)
{
    char caller[L_tmpnam];

    if (install_readlink_failure_filter() != 0)
        return 1;

    /* Both source loops accept only raw -ENOENT. The filter returns raw
     * -ELOOP instead, so each public entry must exhaust its bounded retries
     * without writing C errno. */
    errno = FIXTURE_UNCHANGED_ERRNO;
    if (tmpnam(caller) != (char *)0 || errno != FIXTURE_UNCHANGED_ERRNO)
        return 2;

    errno = FIXTURE_UNCHANGED_ERRNO;
    if (tempnam((const char *)0, (const char *)0) != (char *)0 ||
        errno != FIXTURE_UNCHANGED_ERRNO)
        return 3;
    return 0;
}

int crabc_x86_64_temporary_names_probe(void)
{
#ifdef CRABC_TEMPORARY_NAMES_CANDIDATE
    if (__crabc_x86_temporary_names_v1() != 1)
        return 100;
#endif
    if (check_tmpnam() != 0)
        return 1;
    if (check_tempnam() != 0)
        return 2;
    if (check_readlink_failure_retry() != 0)
        return 3;
    return 0;
}

int main(void)
{
    return crabc_x86_64_temporary_names_probe();
}
