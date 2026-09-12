/* Native x86-64 musl compatibility-entry behavior probe.
 *
 * The installed candidate headers supply every ordinary C declaration.  The
 * fourteen historical spellings have no installed public declaration, so their
 * source-faithful ABI declarations are intentionally local to this probe.
 * The `__strto*_internal` declarations retain the historical fourth `group`
 * argument: musl 1.2.6 aliases each name to a three-argument strto entry, so
 * the System V x86-64 extra argument is accepted and ignored.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(long) == 8 && sizeof(long long) == 8, "LP64 integer ABI");
_Static_assert(sizeof(dev_t) == sizeof(unsigned long), "x86 Linux dev_t ABI");

extern int __isoc99_fscanf(FILE *, const char *, ...);
extern int __isoc99_scanf(const char *, ...);
extern int __isoc99_sscanf(const char *, const char *, ...);
extern int __isoc99_vfscanf(FILE *, const char *, va_list);
extern int __isoc99_vscanf(const char *, va_list);
extern int __isoc99_vsscanf(const char *, const char *, va_list);

extern long __strtol_internal(const char *, char **, int, int);
extern long long __strtoll_internal(const char *, char **, int, int);
extern unsigned long __strtoul_internal(const char *, char **, int, int);
extern unsigned long long __strtoull_internal(const char *, char **, int, int);
extern intmax_t __strtoimax_internal(const char *, char **, int, int);
extern uintmax_t __strtoumax_internal(const char *, char **, int, int);
extern int __xmknod(int, const char *, mode_t, dev_t *);
extern int __xmknodat(int, int, const char *, mode_t, dev_t *);

static int call_vsscanf(const char *input, const char *format, ...)
{
    va_list arguments;
    int result;
    va_start(arguments, format);
    result = __isoc99_vsscanf(input, format, arguments);
    va_end(arguments);
    return result;
}

static int call_vfscanf(FILE *stream, const char *format, ...)
{
    va_list arguments;
    int result;
    va_start(arguments, format);
    result = __isoc99_vfscanf(stream, format, arguments);
    va_end(arguments);
    return result;
}

static int call_vscanf(const char *format, ...)
{
    va_list arguments;
    int result;
    va_start(arguments, format);
    result = __isoc99_vscanf(format, arguments);
    va_end(arguments);
    return result;
}

static int check_scan_aliases(const char *stream_path)
{
    int number = 0;
    int first = 0;
    int second = 0;
    int saved_stdin;
    int pipe_fds[2];
    char word[8] = {0};
    FILE *stream;

    if (__isoc99_fscanf != fscanf || __isoc99_scanf != scanf ||
        __isoc99_sscanf != sscanf || __isoc99_vfscanf != vfscanf ||
        __isoc99_vscanf != vscanf || __isoc99_vsscanf != vsscanf)
        return 1;
    if (__isoc99_sscanf("17 tail", "%d %4s", &number, word) != 2 ||
        number != 17 || strcmp(word, "tail"))
        return 2;
    memset(word, 0, sizeof word);
    if (call_vsscanf("29 word", "%d %4s", &number, word) != 2 ||
        number != 29 || strcmp(word, "word"))
        return 3;

    stream = fopen(stream_path, "w+");
    if (!stream || fputs("41 file", stream) < 0 || fseek(stream, 0, SEEK_SET))
        return 4;
    memset(word, 0, sizeof word);
    if (__isoc99_fscanf(stream, "%d", &number) != 1 || number != 41 ||
        call_vfscanf(stream, " %4s", word) != 1 || strcmp(word, "file") || fclose(stream))
        return 5;
    if (unlink(stream_path))
        return 6;

    saved_stdin = dup(0);
    if (saved_stdin < 0 || pipe(pipe_fds) || write(pipe_fds[1], "53 59", 5) != 5)
        return 7;
    if (close(pipe_fds[1]) || dup2(pipe_fds[0], 0) != 0 || close(pipe_fds[0]))
        return 8;
    if (__isoc99_scanf("%d", &first) != 1 || call_vscanf("%d", &second) != 1 ||
        first != 53 || second != 59)
        return 9;
    if (dup2(saved_stdin, 0) != 0 || close(saved_stdin))
        return 10;
    clearerr(stdin);
    return 0;
}

static int check_integer_aliases(void)
{
    static const char signed_input[] = " -42!";
    static const char unsigned_input[] = "0x2a!";
    char *end = 0;
    long signed_zero_group;

    errno = EINTR;
    signed_zero_group = __strtol_internal(signed_input, &end, 10, 0);
    if (signed_zero_group != -42 || end != signed_input + 4 || errno != EINTR)
        return 10;
    errno = EINTR;
    if (__strtol_internal(signed_input, &end, 10, 91) != signed_zero_group ||
        end != signed_input + 4 || errno != EINTR)
        return 11;
    errno = EINTR;
    if (__strtoll_internal(signed_input, &end, 10, -7) != -42 ||
        end != signed_input + 4 || errno != EINTR)
        return 12;
    errno = EINTR;
    if (__strtoul_internal(unsigned_input, &end, 0, 1) != 42UL ||
        end != unsigned_input + 4 || errno != EINTR)
        return 13;
    errno = EINTR;
    if (__strtoull_internal(unsigned_input, &end, 0, 2) != 42ULL ||
        end != unsigned_input + 4 || errno != EINTR)
        return 14;
    errno = EINTR;
    if (__strtoimax_internal(signed_input, &end, 10, 3) != (intmax_t)-42 ||
        end != signed_input + 4 || errno != EINTR)
        return 15;
    errno = EINTR;
    if (__strtoumax_internal(unsigned_input, &end, 0, 4) != (uintmax_t)42 ||
        end != unsigned_input + 4 || errno != EINTR)
        return 16;
    return 0;
}

static int check_mknod_wrappers(const char *fifo_path, const char *directory_path)
{
    dev_t device = 0;
    struct stat metadata;
    int directory;

    if (__xmknod(-19, fifo_path, S_IFIFO | 0600, &device) != 0 ||
        lstat(fifo_path, &metadata) != 0 || !S_ISFIFO(metadata.st_mode))
        return 20;
    if (unlink(fifo_path))
        return 21;
    directory = open(directory_path, O_RDONLY | O_DIRECTORY);
    if (directory < 0)
        return 22;
    if (__xmknodat(73, directory, "entry-fifo", S_IFIFO | 0600, &device) != 0 ||
        fstatat(directory, "entry-fifo", &metadata, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISFIFO(metadata.st_mode))
        return 23;
    if (unlinkat(directory, "entry-fifo", 0) || close(directory))
        return 24;
    errno = 0;
    if (__xmknodat(11, -1, "not-reached", S_IFIFO | 0600, &device) != -1 || errno != EBADF)
        return 25;
    return 0;
}

int main(int argc, char **argv)
{
    int status;
    if (argc != 3)
        return 90;
    status = check_scan_aliases(argv[1]);
    if (status)
        return status;
    status = check_integer_aliases();
    if (status)
        return status;
    status = check_mknod_wrappers(argv[1], argv[2]);
    if (status)
        return status;
    return write(1, "c-compatibility-entry-aliases-ok\n", 33) == 33 ? 0 : 91;
}
