/* Pinned-musl temporary-object differential over an isolated directory. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef FIXTURE_ROOT
#error FIXTURE_ROOT must name the isolated fixture directory
#endif

static long call1(long number, long a)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a) : "rcx", "r11", "memory");
    return result;
}

static long call2(long number, long a, long b)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a), "S"(b) : "rcx", "r11", "memory");
    return result;
}

static long call3(long number, long a, long b, long c)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return result;
}

static long call4(long number, long a, long b, long c, long d)
{
    register long r10 __asm__("r10") = d;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return result;
}

static int same(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static void copy(char *out, const char *in)
{
    while ((*out++ = *in++) != 0) {}
}

static void append(char *out, const char *in)
{
    while (*out) ++out;
    copy(out, in);
}

static size_t length(const char *text)
{
    size_t result = 0;
    while (text[result]) ++result;
    return result;
}

static int suffix_valid(const char *name, const char *prefix, const char *suffix)
{
    size_t i = 0, j = 0, k = 0;
    while (prefix[i]) { if (name[i] != prefix[i]) return 0; ++i; }
    while (j < 6) {
        char c = name[i + j];
        if (!((c >= 'A' && c <= 'P') || (c >= 'a' && c <= 'p'))) return 0;
        ++j;
    }
    while (suffix[k]) { if (name[i + j + k] != suffix[k]) return 0; ++k; }
    return name[i + j + k] == 0;
}

static int raw_stat(const char *path, struct stat *out)
{
    return call4(SYS_newfstatat, AT_FDCWD, (long)(uintptr_t)path, (long)(uintptr_t)out, 0) == 0;
}

static int invalid_templates(void)
{
    char short_name[] = "XXXXX";
    char wrong[] = "abXXXYXX";
    char suffix[] = "abXXXXXX.tag";
    char negative[] = "abXXXXXX.tag";
    char too_long[] = "abXXXXXX.tag";
    char directory[] = "abXXXXXY";
    errno = 0;
    if (mkstemp(short_name) != -1 || errno != EINVAL || !same(short_name, "XXXXX")) return 1;
    errno = 0;
    if (mkstemp(wrong) != -1 || errno != EINVAL || !same(wrong, "abXXXYXX")) return 2;
    errno = 0;
    if (mkstemps(suffix, 0) != -1 || errno != EINVAL || !same(suffix, "abXXXXXX.tag")) return 3;
    errno = 0;
    if (mkstemps(negative, -1) != -1 || errno != EINVAL || !same(negative, "abXXXXXX.tag")) return 4;
    errno = 0;
    if (mkostemps(too_long, 100, 0) != -1 || errno != EINVAL || !same(too_long, "abXXXXXX.tag")) return 5;
    errno = 0;
    if (mkdtemp(directory) != NULL || errno != EINVAL || !same(directory, "abXXXXXY")) return 6;
    return 0;
}

static int failed_creation_restores_template(void)
{
    char file[512], file_original[512], directory[512], directory_original[512];
    copy(file, FIXTURE_ROOT "/absent/file-XXXXXX");
    copy(file_original, file);
    errno = 0;
    if (mkstemp(file) != -1 || errno != ENOENT || !same(file, file_original)) return 7;
    copy(directory, FIXTURE_ROOT "/absent/dir-XXXXXX");
    copy(directory_original, directory);
    errno = 0;
    if (mkdtemp(directory) != NULL || errno != ENOENT || !same(directory, directory_original))
        return 8;
    return 0;
}

static int file_case(const char *stem, const char *extension, int kind, int flags,
                     int expected_mode, int expected_fd_flags, int expected_status_flags)
{
    char name[512], prefix[512];
    struct stat path_stat, fd_stat;
    int fd;
    copy(prefix, FIXTURE_ROOT);
    append(prefix, "/");
    append(prefix, stem);
    copy(name, prefix);
    append(name, "XXXXXX");
    append(name, extension);
    if (kind == 0) fd = mkstemp(name);
    else if (kind == 1) fd = mkstemps(name, (int)length(extension));
    else if (kind == 2) fd = mkostemp(name, flags);
    else fd = mkostemps(name, (int)length(extension), flags);
    if (fd < 0) return 10 + kind;
    if (!suffix_valid(name, prefix, extension)) return 20 + kind;
    if (!raw_stat(name, &path_stat) || call2(SYS_fstat, fd, (long)(uintptr_t)&fd_stat) != 0)
        return 30 + kind;
    if (!S_ISREG(path_stat.st_mode) || (path_stat.st_mode & 0777) != expected_mode ||
        path_stat.st_ino != fd_stat.st_ino || path_stat.st_nlink != 1)
        return 40 + kind;
    if (((int)call2(SYS_fcntl, fd, F_GETFD) & FD_CLOEXEC) != expected_fd_flags ||
        ((int)call2(SYS_fcntl, fd, F_GETFL) & (O_ACCMODE | O_APPEND)) != expected_status_flags)
        return 50 + kind;
    if (call3(SYS_unlinkat, AT_FDCWD, (long)(uintptr_t)name, 0) != 0) return 60 + kind;
    if (raw_stat(name, &path_stat)) return 70 + kind;
    if (call2(SYS_fstat, fd, (long)(uintptr_t)&fd_stat) != 0 || fd_stat.st_nlink != 0)
        return 80 + kind;
    if (call1(SYS_close, fd) != 0) return 90 + kind;
    return 0;
}

static int directory_case(const char *stem, int expected_mode)
{
    char name[512], prefix[512];
    struct stat value;
    copy(prefix, FIXTURE_ROOT);
    append(prefix, "/");
    append(prefix, stem);
    copy(name, prefix);
    append(name, "XXXXXX");
    if (mkdtemp(name) != name || !suffix_valid(name, prefix, "")) return 100;
    if (!raw_stat(name, &value) || !S_ISDIR(value.st_mode) ||
        (value.st_mode & 0777) != expected_mode) return 101;
    if (call3(SYS_unlinkat, AT_FDCWD, (long)(uintptr_t)name, AT_REMOVEDIR) != 0) return 102;
    if (raw_stat(name, &value)) return 103;
    return 0;
}

int crabc_x86_64_temporary_objects_probe(void)
{
    int status;
    long old_mask = call1(SYS_umask, 0);
    if (old_mask < 0) return 110;
    status = invalid_templates();
    if (status) return status;
    status = file_case("plain-", "", 0, 0, 0600, 0, O_RDWR);
    if (status) return status;
    status = file_case("suffix-", ".tag", 1, 0, 0600, 0, O_RDWR);
    if (status) return status;
    status = file_case("flags-", "", 2, O_WRONLY | O_APPEND | O_CLOEXEC,
                       0600, FD_CLOEXEC, O_RDWR | O_APPEND);
    if (status) return status;
    status = file_case("both-", ".txt", 3, O_CLOEXEC,
                       0600, FD_CLOEXEC, O_RDWR);
    if (status) return status;
    status = directory_case("dir-", 0700);
    if (status) return status;
    if (call1(SYS_umask, 0200) < 0) return 111;
    status = file_case("mask-", "", 0, 0, 0400, 0, O_RDWR);
    if (status) return status;
    if (call1(SYS_umask, 0100) < 0) return 112;
    status = directory_case("maskdir-", 0600);
    if (status) return status;
    status = failed_creation_restores_template();
    if (status) return status;
    if (call1(SYS_umask, old_mask) < 0) return 113;
    call3(SYS_write, 1, (long)(uintptr_t)"temporary-objects:PASS\n", 23);
    return 0;
}

#ifndef CRABC_TEMPORARY_OBJECTS_FREESTANDING
int main(void) { return crabc_x86_64_temporary_objects_probe(); }
#endif
