/* Static x86-64 permanent-standard-stream status regression fixture.
 *
 * The same project-header source first executes through pinned musl 1.2.6,
 * then through one true -nostdlib/-static crabc archive. It calls only
 * feof/ferror/clearerr on the process-lifetime stdin object. One fgetc call is
 * used solely to create each observed EOF or EBADF error indicator; this is
 * status-transition setup, not byte-I/O evidence.
 *
 * The C/POSIX predicate contract is zero versus nonzero. Musl's internal
 * locking and numeric `1` normalization, pathname FILE objects, multiple
 * streams, unlocked aliases, block I/O, buffer configuration, and general
 * FILE state remain outside this leaf.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

typedef int (*close_fn)(int);
typedef int (*dup_fn)(int);
typedef int (*dup2_fn)(int, int);
typedef int (*fgetc_fn)(FILE *);
typedef int (*status_predicate_fn)(FILE *);
typedef void (*status_clear_fn)(FILE *);
typedef int (*pipe_fn)(int *);

static close_fn volatile close_entry = close;
static dup_fn volatile dup_entry = dup;
static dup2_fn volatile dup2_entry = dup2;
static fgetc_fn volatile fgetc_entry = fgetc;
static status_predicate_fn volatile feof_entry = feof;
static status_predicate_fn volatile ferror_entry = ferror;
static status_clear_fn volatile clearerr_entry = clearerr;
static pipe_fn volatile pipe_entry = pipe;

static int save_descriptor(int descriptor, int *saved)
{
    *saved = dup_entry(descriptor);
    if (*saved >= 0)
        return 0;
    return errno == EBADF ? 0 : -1;
}

static int restore_descriptor(int descriptor, int saved)
{
    if (saved < 0) {
        if (close_entry(descriptor) == 0 || errno == EBADF)
            return 0;
        return -1;
    }
    if (dup2_entry(saved, descriptor) != descriptor) {
        (void)close_entry(saved);
        return -1;
    }
    return close_entry(saved) == 0 ? 0 : -1;
}

/* Redirect stdin to a pipe whose write end has already been closed, producing
 * a deterministic zero-read EOF transition without creating a FILE object. */
static int redirect_empty_input(int *saved)
{
    int descriptors[2] = {-1, -1};
    int status = -1;

    if (save_descriptor(STDIN_FILENO, saved) != 0 ||
        pipe_entry(descriptors) != 0)
        goto cleanup;
    if (close_entry(descriptors[1]) != 0)
        goto cleanup;
    descriptors[1] = -1;
    if (descriptors[0] != STDIN_FILENO &&
        dup2_entry(descriptors[0], STDIN_FILENO) != STDIN_FILENO)
        goto cleanup;
    if (descriptors[0] != STDIN_FILENO &&
        close_entry(descriptors[0]) != 0)
        goto cleanup;
    descriptors[0] = -1;
    status = 0;

cleanup:
    if (descriptors[0] >= 0)
        (void)close_entry(descriptors[0]);
    if (descriptors[1] >= 0)
        (void)close_entry(descriptors[1]);
    return status;
}

static int check_permanent_stdin_status_transitions(void)
{
    int saved = -1;
    int status = 0;

    if (redirect_empty_input(&saved) != 0)
        return 1;
    if (fgetc_entry(stdin) != EOF) {
        status = 2;
        goto cleanup;
    }
    if (feof_entry(stdin) == 0 || ferror_entry(stdin) != 0) {
        status = 3;
        goto cleanup;
    }
    clearerr_entry(stdin);
    if (feof_entry(stdin) != 0 || ferror_entry(stdin) != 0) {
        status = 4;
        goto cleanup;
    }
    if (close_entry(STDIN_FILENO) != 0) {
        status = 5;
        goto cleanup;
    }
    if (fgetc_entry(stdin) != EOF) {
        status = 6;
        goto cleanup;
    }
    if (feof_entry(stdin) != 0 || ferror_entry(stdin) == 0) {
        status = 7;
        goto cleanup;
    }
    clearerr_entry(stdin);
    if (feof_entry(stdin) != 0 || ferror_entry(stdin) != 0)
        status = 8;

cleanup:
    if (restore_descriptor(STDIN_FILENO, saved) != 0 && status == 0)
        status = 9;
    return status;
}

int crabc_x86_64_stdio_permanent_status_probe(void)
{
    return check_permanent_stdin_status_transitions();
}

#ifndef CRABC_STDIO_PERMANENT_STATUS_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_status_probe();
}
#endif
