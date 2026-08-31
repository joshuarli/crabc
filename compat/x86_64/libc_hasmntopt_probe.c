/* Static x86-64 hasmntopt C ABI and behavior fixture.
 *
 * The identical project-header body runs first through pinned musl 1.2.6 and
 * then through a freestanding crabc archive candidate. It exercises only the
 * caller-owned comma-delimited mnt_opts scan, including whole-token, equals
 * suffix, duplicate, interior-substring, empty-token, and short-final-token
 * guard-page behavior. It does not open or parse an mtab file, invoke mount
 * APIs, or make filesystem/I/O claims.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <mntent.h>
#include <stddef.h>

_Static_assert(sizeof(struct mntent) == 40 && _Alignof(struct mntent) == 8,
    "x86 mntent record layout");
_Static_assert(offsetof(struct mntent, mnt_opts) == 24,
    "x86 mntent options field offset");
_Static_assert(__builtin_types_compatible_p(__typeof__(&hasmntopt),
    char *(*)(const struct mntent *, const char *)), "hasmntopt declaration");

typedef char *(*hasmntopt_signature)(const struct mntent *, const char *);

enum {
    CRABC_X86_PAGE_SIZE = 4096,
    CRABC_LINUX_SYS_MMAP = 9,
    CRABC_LINUX_SYS_MPROTECT = 10,
    CRABC_LINUX_SYS_MUNMAP = 11,
    CRABC_LINUX_PROT_NONE = 0,
    CRABC_LINUX_PROT_READ_WRITE = 3,
    CRABC_LINUX_MAP_PRIVATE_ANONYMOUS = 0x22,
};

static char source_name[] = "fixture-source";
static char mount_directory[] = "/fixture";
static char filesystem_type[] = "fixture-type";
static char primary_options[] = "rw,relatime,nosuid,ro=bind,ro";
static const char primary_original[] = "rw,relatime,nosuid,ro=bind,ro";
static char separator_options[] = "alpha,,=,omega";
static char empty_options[] = "";

static struct mntent primary_entry = {
    source_name, mount_directory, filesystem_type, primary_options, 0, 0,
};
static struct mntent separator_entry = {
    source_name, mount_directory, filesystem_type, separator_options, 0, 0,
};
static struct mntent empty_entry = {
    source_name, mount_directory, filesystem_type, empty_options, 0, 0,
};

static long raw_syscall2(long number, long first, long second)
{
    long result;
    __asm__ volatile ("syscall"
        : "=a" (result)
        : "a" (number), "D" (first), "S" (second)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long first, long second, long third)
{
    long result;
    __asm__ volatile ("syscall"
        : "=a" (result)
        : "a" (number), "D" (first), "S" (second), "d" (third)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall6(long number, long first, long second, long third,
    long fourth, long fifth, long sixth)
{
    register long r10 __asm__("r10") = fourth;
    register long r8 __asm__("r8") = fifth;
    register long r9 __asm__("r9") = sixth;
    long result;
    __asm__ volatile ("syscall"
        : "=a" (result), "+r" (r10), "+r" (r8), "+r" (r9)
        : "a" (number), "D" (first), "S" (second), "d" (third)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_is_linux_error(long value)
{
    return value < 0 && value >= -4095;
}

static int bytes_match(const char *left, const char *right)
{
    for (;;) {
        if (*left != *right)
            return 0;
        if (*left == 0)
            return 1;
        left++;
        right++;
    }
}

static int check_primary_options(void)
{
    const hasmntopt_signature function = hasmntopt;

    if (hasmntopt(&primary_entry, "rw") != primary_options)
        return 1;
    if (function(&primary_entry, "relatime") != primary_options + 3)
        return 2;
    if (hasmntopt(&primary_entry, "nosuid") != primary_options + 12)
        return 3;
    if (hasmntopt(&primary_entry, "ro") != primary_options + 19)
        return 4;
    if (function(&primary_entry, "ro=bind") != primary_options + 19)
        return 5;
    if (hasmntopt(&primary_entry, "ro=other") != 0)
        return 6;
    if (hasmntopt(&primary_entry, "r") != 0)
        return 7;
    if (function(&primary_entry, "bind") != 0)
        return 8;
    if (hasmntopt(&primary_entry, "uid") != 0)
        return 9;
    if (hasmntopt(&primary_entry, "missing") != 0)
        return 10;
    return bytes_match(primary_options, primary_original) ? 0 : 11;
}

static int check_empty_options(void)
{
    const hasmntopt_signature function = hasmntopt;

    if (hasmntopt(&separator_entry, "") != separator_options + 6)
        return 1;
    if (function(&separator_entry, "=") != separator_options + 7)
        return 2;
    if (hasmntopt(&separator_entry, "alpha=") != 0)
        return 3;
    if (hasmntopt(&empty_entry, "") != empty_options)
        return 4;
    if (function(&empty_entry, "alpha") != 0)
        return 5;
    return 0;
}

static int check_short_token_guard_page(void)
{
    long mapping = raw_syscall6(CRABC_LINUX_SYS_MMAP, 0,
        2 * CRABC_X86_PAGE_SIZE, CRABC_LINUX_PROT_READ_WRITE,
        CRABC_LINUX_MAP_PRIVATE_ANONYMOUS, -1, 0);
    char *options;
    struct mntent entry;
    long cleanup;

    if (raw_is_linux_error(mapping))
        return 1;
    options = (char *)mapping + CRABC_X86_PAGE_SIZE - 2;
    options[0] = 'r';
    options[1] = 0;
    entry.mnt_fsname = source_name;
    entry.mnt_dir = mount_directory;
    entry.mnt_type = filesystem_type;
    entry.mnt_opts = options;
    entry.mnt_freq = 0;
    entry.mnt_passno = 0;
    if (raw_syscall3(CRABC_LINUX_SYS_MPROTECT,
            (long)(options + 2), CRABC_X86_PAGE_SIZE,
            CRABC_LINUX_PROT_NONE) != 0) {
        (void)raw_syscall2(CRABC_LINUX_SYS_MUNMAP, mapping,
            2 * CRABC_X86_PAGE_SIZE);
        return 2;
    }

    /* Musl's `&&` skips p[l] after strncmp finds r != x at the terminal NUL. */
    if (hasmntopt(&entry, "rx") != 0) {
        (void)raw_syscall2(CRABC_LINUX_SYS_MUNMAP, mapping,
            2 * CRABC_X86_PAGE_SIZE);
        return 3;
    }
    cleanup = raw_syscall2(CRABC_LINUX_SYS_MUNMAP, mapping,
        2 * CRABC_X86_PAGE_SIZE);
    return cleanup == 0 ? 0 : 4;
}

int crabc_x86_64_hasmntopt_probe(void)
{
    int status = check_primary_options();

    if (status != 0)
        return 10 + status;
    status = check_empty_options();
    if (status != 0)
        return 30 + status;
    status = check_short_token_guard_page();
    return status == 0 ? 0 : 50 + status;
}

#ifndef CRABC_HASMNTOPT_FREESTANDING
int main(void)
{
    return crabc_x86_64_hasmntopt_probe();
}
#endif
