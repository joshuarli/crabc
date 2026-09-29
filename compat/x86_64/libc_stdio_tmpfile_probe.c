/* Static x86-64 bounded tmpfile regression fixture.
 *
 * The same project-header source first executes against pinned musl 1.2.6,
 * then against one -nostdlib/-static crabc archive. It proves the observable
 * unnamed-file, descriptor, read/write, LP64 tmpfile64-macro, independent
 * handles, and close/fork lifecycle within two fixed stream records.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef tmpfile64
#error "Linux LP64 must expose tmpfile64 as a preprocessing alias"
#endif

typedef int (*fclose_fn)(FILE *);
typedef int (*fcntl_fn)(int, int, ...);
typedef int (*fileno_fn)(FILE *);
typedef int (*fseek_fn)(FILE *, long, int);
typedef int (*fstat_fn)(int, struct stat *);
typedef size_t (*fread_fn)(void *, size_t, size_t, FILE *);
typedef size_t (*fwrite_fn)(const void *, size_t, size_t, FILE *);
typedef FILE *(*tmpfile_fn)(void);
typedef mode_t (*umask_fn)(mode_t);

static fclose_fn volatile fclose_entry = fclose;
static fcntl_fn volatile fcntl_entry = fcntl;
static fileno_fn volatile fileno_entry = fileno;
static fseek_fn volatile fseek_entry = fseek;
static fstat_fn volatile fstat_entry = fstat;
static fread_fn volatile fread_entry = fread;
static fwrite_fn volatile fwrite_entry = fwrite;
static tmpfile_fn volatile tmpfile_entry = tmpfile;
static tmpfile_fn volatile tmpfile64_entry = tmpfile64;
static umask_fn volatile umask_entry = umask;

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t length)
{
    size_t index;

    for (index = 0; index != length; ++index)
        if (left[index] != right[index])
            return 0;
    return 1;
}

static int check_unlinked(int descriptor)
{
    static const char prefix[] = "/proc/self/fd/";
    static const char suffix[] = " (deleted)";
    char descriptor_path[sizeof(prefix) + 10];
    char digits[10];
    char target[256];
    struct stat state;
    size_t count = 0;
    size_t index;
    ssize_t length;
    unsigned int value;

    if (descriptor < 0)
        return 0;
    for (index = 0; index < sizeof(prefix) - 1; ++index)
        descriptor_path[index] = prefix[index];
    value = (unsigned int)descriptor;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0 && count < sizeof(digits));
    if (value != 0)
        return 0;
    for (index = 0; index < count; ++index)
        descriptor_path[sizeof(prefix) - 1 + index] = digits[count - 1 - index];
    descriptor_path[sizeof(prefix) - 1 + count] = '\0';

    length = readlink(descriptor_path, target, sizeof(target) - 1);
    if (length < (ssize_t)(sizeof(suffix) - 1) ||
        length >= (ssize_t)sizeof(target))
        return 0;
    for (index = 0; index < sizeof(suffix) - 1; ++index)
        if (target[length - (ssize_t)(sizeof(suffix) - 1) + (ssize_t)index] !=
            suffix[index])
            return 0;
    target[length - (ssize_t)(sizeof(suffix) - 1)] = '\0';
    errno = 0;
    return stat(target, &state) == -1 && errno == ENOENT;
}

static int check_tmpfile(void)
{
    static const unsigned char payload[] = {0x00, 0x74, 0x6d, 0x70, 0xff};
    unsigned char observed[sizeof(payload)];
    struct stat state;
    struct stat parallel_state;
    FILE *stream = NULL;
    FILE *parallel = NULL;
#ifdef CRABC_STDIO_TMPFILE_FREESTANDING
    FILE *overflow;
#endif
    FILE *reused = NULL;
    mode_t old_mask;
    int descriptor;
    int status = 0;

    if (tmpfile_entry != tmpfile64_entry)
        return 1;

    old_mask = umask_entry(0);
    stream = tmpfile64_entry();
    (void)umask_entry(old_mask);
    if (stream == NULL)
        return 2;
    descriptor = fileno_entry(stream);
    if (descriptor < 0 || fstat_entry(descriptor, &state) != 0) {
        status = 3;
        goto close_stream;
    }
    if ((state.st_mode & S_IFMT) != S_IFREG ||
        (state.st_mode & 0777) != 0600 || state.st_nlink != 0 ||
        !check_unlinked(descriptor)) {
        status = 4;
        goto close_stream;
    }
    if ((fcntl_entry(descriptor, F_GETFL) & O_ACCMODE) != O_RDWR ||
        fcntl_entry(descriptor, F_GETFD) != 0) {
        status = 5;
        goto close_stream;
    }
    if (fwrite_entry(payload, 1, sizeof(payload), stream) != sizeof(payload) ||
        fseek_entry(stream, 0, SEEK_SET) != 0 ||
        fread_entry(observed, 1, sizeof(observed), stream) != sizeof(observed) ||
        !bytes_equal(observed, payload, sizeof(payload))) {
        status = 6;
        goto close_stream;
    }

    parallel = tmpfile_entry();
    if (parallel == NULL) {
        status = 7;
        goto close_stream;
    }
    if (parallel == stream || fileno_entry(parallel) == descriptor ||
        fstat_entry(fileno_entry(parallel), &parallel_state) != 0 ||
        parallel_state.st_nlink != 0 ||
        (parallel_state.st_dev == state.st_dev &&
         parallel_state.st_ino == state.st_ino) ||
        !check_unlinked(fileno_entry(parallel))) {
        status = 14;
        goto close_stream;
    }
#ifdef CRABC_STDIO_TMPFILE_FREESTANDING
    errno = 0;
    overflow = tmpfile_entry();
    if (overflow != NULL) {
        (void)fclose_entry(overflow);
        status = 27;
        goto close_stream;
    }
    if (errno != EMFILE) {
        status = 28;
        goto close_stream;
    }
#endif
    if (fwrite_entry(payload, 1, sizeof(payload), parallel) != sizeof(payload) ||
        fseek_entry(parallel, 0, SEEK_SET) != 0 ||
        fread_entry(observed, 1, sizeof(observed), parallel) != sizeof(observed) ||
        !bytes_equal(observed, payload, sizeof(payload))) {
        status = 16;
        goto close_stream;
    }
    if (fseek_entry(stream, 0, SEEK_SET) != 0 ||
        fread_entry(observed, 1, sizeof(observed), stream) != sizeof(observed) ||
        !bytes_equal(observed, payload, sizeof(payload))) {
        status = 17;
        goto close_stream;
    }
    if (fclose_entry(stream) != 0) {
        status = 18;
        stream = NULL;
        goto close_stream;
    }
    stream = NULL;
    errno = 0;
    if (fcntl_entry(descriptor, F_GETFD) != -1 || errno != EBADF ||
        fseek_entry(parallel, 0, SEEK_SET) != 0 ||
        fread_entry(observed, 1, sizeof(observed), parallel) != sizeof(observed) ||
        !bytes_equal(observed, payload, sizeof(payload))) {
        status = 19;
        goto close_stream;
    }

close_stream:
    if (parallel != NULL && fclose_entry(parallel) != 0 && status == 0)
        status = 15;
    if (stream != NULL && fclose_entry(stream) != 0 && status == 0)
        status = 8;
    stream = NULL;
    if (status != 0)
        return status;
    errno = 0;
    if (fcntl_entry(descriptor, F_GETFD) != -1 || errno != EBADF)
        return 9;

    /* Musl passes 0600 directly to open(2), so the process umask continues
     * to mask that requested mode. Keep this separate from the zero-umask
     * check above: the slot remains single-live and is reused only after the
     * first stream has retired. */
    old_mask = umask_entry(0600);
    reused = tmpfile_entry();
    (void)umask_entry(old_mask);
    if (reused == NULL)
        return 10;
    descriptor = fileno_entry(reused);
    if (descriptor < 0 || fstat_entry(descriptor, &state) != 0) {
        (void)fclose_entry(reused);
        return 11;
    }
    if ((state.st_mode & 0777) != 0) {
        (void)fclose_entry(reused);
        return 12;
    }
    if (fclose_entry(reused) != 0)
        return 13;
    return 0;
}

static int check_fork(void)
{
    static const unsigned char payload[] = {0x66, 0x6f, 0x72, 0x6b};
    unsigned char observed[sizeof(payload)];
    struct stat parent_state;
    struct stat child_state;
    FILE *stream;
    pid_t child;
    int descriptor;
    int wait_status;
    int status = 0;

    stream = tmpfile_entry();
    if (stream == NULL)
        return 20;
    descriptor = fileno_entry(stream);
    if (descriptor < 0 || fstat_entry(descriptor, &parent_state) != 0 ||
        parent_state.st_nlink != 0 ||
        fwrite_entry(payload, 1, sizeof(payload), stream) != sizeof(payload) ||
        fseek_entry(stream, 0, SEEK_SET) != 0) {
        status = 21;
        goto close_stream;
    }
    child = fork();
    if (child == -1) {
        status = 22;
        goto close_stream;
    }
    if (child == 0) {
        int child_ok = fstat_entry(descriptor, &child_state) == 0 &&
            child_state.st_dev == parent_state.st_dev &&
            child_state.st_ino == parent_state.st_ino &&
            child_state.st_nlink == 0 &&
            fread_entry(observed, 1, sizeof(observed), stream) == sizeof(observed) &&
            bytes_equal(observed, payload, sizeof(payload)) &&
            fclose_entry(stream) == 0;
        _exit(child_ok ? 0 : 1);
    }
    if (waitpid(child, &wait_status, 0) != child ||
        !WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0) {
        status = 23;
        goto close_stream;
    }
    if (fstat_entry(descriptor, &parent_state) != 0 || parent_state.st_nlink != 0 ||
        fseek_entry(stream, 0, SEEK_SET) != 0 ||
        fread_entry(observed, 1, sizeof(observed), stream) != sizeof(observed) ||
        !bytes_equal(observed, payload, sizeof(payload))) {
        status = 24;
        goto close_stream;
    }
close_stream:
    if (fclose_entry(stream) != 0 && status == 0)
        status = 25;
    errno = 0;
    if (status == 0 && (fcntl_entry(descriptor, F_GETFD) != -1 || errno != EBADF))
        status = 26;
    return status;
}

int crabc_x86_64_stdio_tmpfile_probe(void)
{
    int status = check_tmpfile();

    if (status != 0)
        return status;
    status = check_fork();
    if (status != 0)
        return status;
    {
        static const char report[] =
            "tmpfile: unlinked distinct handles, isolated close, inherited fork\n";
        if (write(1, report, sizeof(report) - 1) != sizeof(report) - 1)
            return 29;
    }
    return 0;
}

#ifndef CRABC_STDIO_TMPFILE_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_tmpfile_probe();
}
#endif
