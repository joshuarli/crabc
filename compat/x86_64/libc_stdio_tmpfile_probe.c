/* Static x86-64 bounded tmpfile regression fixture.
 *
 * The same project-header source first executes against pinned musl 1.2.6,
 * then against one -nostdlib/-static crabc archive. It proves the observable
 * unnamed-file, descriptor, read/write, LP64 tmpfile64-macro, close, and fixed
 * slot lifecycle only. It is not a general stream allocator, path-stream
 * capability completion, or public x86 proof.
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

static int check_tmpfile(void)
{
    static const unsigned char payload[] = {0x00, 0x74, 0x6d, 0x70, 0xff};
    unsigned char observed[sizeof(payload)];
    struct stat state;
    FILE *stream = NULL;
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
        (state.st_mode & 0777) != 0600 || state.st_nlink != 0) {
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

#ifdef CRABC_STDIO_TMPFILE_FREESTANDING
    errno = 0;
    if (tmpfile_entry() != NULL || errno != EMFILE) {
        status = 7;
        goto close_stream;
    }
#endif

close_stream:
    if (fclose_entry(stream) != 0 && status == 0)
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

int crabc_x86_64_stdio_tmpfile_probe(void)
{
    return check_tmpfile();
}

#ifndef CRABC_STDIO_TMPFILE_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_tmpfile_probe();
}
#endif
