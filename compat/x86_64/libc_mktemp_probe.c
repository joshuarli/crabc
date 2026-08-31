/* Static crabc-libc x86-64 mktemp compatibility fixture.
 *
 * The same GNU-enabled C body first runs through pinned musl 1.2.6 and then
 * through a true freestanding crabc archive. Fixture-local raw namespace
 * setup creates one disposable directory and a self-referential symlink only
 * to observe the selected legacy C function's generated-name, EINVAL,
 * ENOENT, and non-ENOENT clearing behavior. It does not make `mktemp` a
 * reservation, create/open a selected pathname, select tmpnam/tempnam or a
 * mkstemp-family API, or select file-handle authority APIs.
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
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>

enum {
    FIXTURE_AT_FDCWD = -100,
    FIXTURE_AT_REMOVEDIR = 0x200,
    FIXTURE_ENOENT = 2,
    FIXTURE_EINVAL = 22,
    FIXTURE_ELOOP = 40,
    FIXTURE_PATH_BYTES = 160,
    FIXTURE_STAT_BYTES = 144,
};

struct stat_scratch_x86 {
    uint8_t bytes[FIXTURE_STAT_BYTES];
} __attribute__((aligned(8)));

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_getpid == 39 && SYS_exit == 60 && SYS_mkdirat == 258 &&
    SYS_newfstatat == 262 && SYS_unlinkat == 263 && SYS_symlinkat == 266,
    "x86 mktemp fixture syscall numbers");
_Static_assert(sizeof(struct stat_scratch_x86) == FIXTURE_STAT_BYTES &&
    _Alignof(struct stat_scratch_x86) == 8,
    "x86 private stat output scratch");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mktemp),
    char *(*)(char *)), "mktemp declaration");
_Static_assert(ENOENT == FIXTURE_ENOENT && EINVAL == FIXTURE_EINVAL &&
    ELOOP == FIXTURE_ELOOP, "Linux mktemp errno values");

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
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

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static size_t string_length(const char *text)
{
    size_t length = 0;

    while (text[length] != '\0')
        ++length;
    return length;
}

static int append_bytes(char *destination, size_t capacity, size_t *length,
    const char *source)
{
    size_t source_length = string_length(source);
    size_t index;

    if (*length + source_length >= capacity)
        return -1;
    for (index = 0; index < source_length; ++index)
        destination[*length + index] = source[index];
    *length += source_length;
    destination[*length] = '\0';
    return 0;
}

static int append_decimal(char *destination, size_t capacity, size_t *length,
    unsigned long value)
{
    char digits[32];
    size_t count = 0;

    do {
        digits[count++] = (char)('0' + value % 10UL);
        value /= 10UL;
    } while (value != 0);
    if (*length + count >= capacity)
        return -1;
    while (count != 0)
        destination[(*length)++] = digits[--count];
    destination[*length] = '\0';
    return 0;
}

static int copy_path(char *destination, size_t capacity, const char *source)
{
    size_t length = 0;

    destination[0] = '\0';
    return append_bytes(destination, capacity, &length, source);
}

static int append_path(char *destination, size_t capacity, const char *piece)
{
    size_t length = string_length(destination);

    return append_bytes(destination, capacity, &length, piece);
}

static int bytes_equal(const char *left, const char *right, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

static int has_musl_randname_alphabet(const char *template)
{
    size_t length = string_length(template);
    size_t index;

    if (length < 6)
        return 0;
    for (index = length - 6; index < length; ++index) {
        if (!((template[index] >= 'A' && template[index] <= 'P') ||
            (template[index] >= 'a' && template[index] <= 'p')))
            return 0;
    }
    return 1;
}

static int path_is_absent(const char *path)
{
    struct stat_scratch_x86 scratch;
    long result = raw_syscall4(SYS_newfstatat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)path, (long)(uintptr_t)&scratch, 0);

    return result == -FIXTURE_ENOENT;
}

static int remove_directory(const char *directory, const char *loop_path)
{
    int failed = 0;

    if (loop_path != (const char *)0 &&
        raw_syscall3(SYS_unlinkat, FIXTURE_AT_FDCWD,
            (long)(uintptr_t)loop_path, 0) != 0)
        failed = 1;
    if (raw_syscall3(SYS_unlinkat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)directory, FIXTURE_AT_REMOVEDIR) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

int crabc_x86_64_mktemp_probe(void)
{
    char directory[FIXTURE_PATH_BYTES] = "/tmp/crabc-mktemp-";
    char valid[FIXTURE_PATH_BYTES];
    char valid_original[FIXTURE_PATH_BYTES];
    char loop_path[FIXTURE_PATH_BYTES];
    char loop_template[FIXTURE_PATH_BYTES];
    char invalid[] = "invalid-XXXXX";
    size_t directory_length = string_length(directory);
    size_t prefix_length;
    int result = 0;

    if (append_decimal(directory, sizeof(directory), &directory_length,
        (unsigned long)raw_syscall0(SYS_getpid)) != 0)
        return 10;
    if (raw_syscall3(SYS_mkdirat, FIXTURE_AT_FDCWD,
        (long)(uintptr_t)directory, 0700) != 0)
        return 11;

    errno = 0;
    if (mktemp(invalid) != invalid || invalid[0] != '\0' || errno != EINVAL) {
        result = 12;
        goto cleanup_directory;
    }

    if (copy_path(valid, sizeof(valid), directory) != 0 ||
        append_path(valid, sizeof(valid), "/candidate-XXXXXX") != 0) {
        result = 13;
        goto cleanup_directory;
    }
    prefix_length = string_length(valid) - 6;
    if (copy_path(valid_original, sizeof(valid_original), valid) != 0) {
        result = 14;
        goto cleanup_directory;
    }
    errno = 0;
    if (mktemp(valid) != valid || errno != ENOENT ||
        !bytes_equal(valid, valid_original, prefix_length) ||
        !has_musl_randname_alphabet(valid) || !path_is_absent(valid)) {
        result = 15;
        goto cleanup_directory;
    }
    if (valid[prefix_length] == '\0') {
        result = 16;
        goto cleanup_directory;
    }

    if (copy_path(loop_path, sizeof(loop_path), directory) != 0 ||
        append_path(loop_path, sizeof(loop_path), "/loop") != 0 ||
        raw_syscall3(SYS_symlinkat, (long)(uintptr_t)"loop",
            FIXTURE_AT_FDCWD, (long)(uintptr_t)loop_path) != 0) {
        result = 17;
        goto cleanup_directory;
    }
    if (copy_path(loop_template, sizeof(loop_template), loop_path) != 0 ||
        append_path(loop_template, sizeof(loop_template), "/XXXXXX") != 0) {
        result = 18;
        goto cleanup_loop;
    }
    errno = 0;
    if (mktemp(loop_template) != loop_template || loop_template[0] != '\0' ||
        errno != ELOOP) {
        result = 19;
        goto cleanup_loop;
    }

cleanup_loop:
    if (remove_directory(directory, loop_path) != 0 && result == 0)
        result = 20;
    return result;

cleanup_directory:
    if (remove_directory(directory, (const char *)0) != 0 && result == 0)
        result = 21;
    return result;
}

#ifndef CRABC_MKTEMP_FREESTANDING
int main(void)
{
    return crabc_x86_64_mktemp_probe();
}
#endif
