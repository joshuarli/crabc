/* Static x86-64 permanent-standard-stream feof_unlocked regression fixture.
 *
 * This project-header source first executes through pinned musl 1.2.6 and
 * then through one true -nostdlib/-static crabc archive. It calls only the
 * GNU/BSD `feof_unlocked` alias and its strong `feof` target on permanent
 * stdin. An empty pipe plus existing fgetc is marker setup solely: both
 * predicates must transition from zero to nonzero. The source makes no claim
 * about musl's numeric `1` normalization, FLOCK/FUNLOCK, lock-free behavior,
 * general FILE state, another status alias, or byte-I/O beyond that marker.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
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
typedef int (*pipe_fn)(int *);
typedef int (*status_predicate_fn)(FILE *);

static close_fn volatile close_entry = close;
static dup_fn volatile dup_entry = dup;
static dup2_fn volatile dup2_entry = dup2;
static fgetc_fn volatile fgetc_entry = fgetc;
static pipe_fn volatile pipe_entry = pipe;
static status_predicate_fn volatile feof_entry = feof;
static status_predicate_fn volatile feof_unlocked_entry = feof_unlocked;

/* Redirect stdin to a pipe whose write end has already been closed, producing
 * a deterministic zero-read EOF marker without creating a FILE object. */
static int redirect_empty_input(int *saved)
{
    int descriptors[2] = {-1, -1};
    int status = -1;

    *saved = dup_entry(STDIN_FILENO);
    if (*saved < 0 || pipe_entry(descriptors) != 0)
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

static int restore_stdin(int saved)
{
    if (dup2_entry(saved, STDIN_FILENO) != STDIN_FILENO) {
        (void)close_entry(saved);
        return -1;
    }
    return close_entry(saved) == 0 ? 0 : -1;
}

int crabc_x86_64_stdio_permanent_feof_unlocked_probe(void)
{
    int saved = -1;
    int status = 0;

    if (feof_unlocked_entry != feof_entry)
        return 1;
    if (redirect_empty_input(&saved) != 0)
        return 2;
    if (feof_entry(stdin) != 0 || feof_unlocked_entry(stdin) != 0) {
        status = 3;
        goto cleanup;
    }
    errno = 0;
    if (fgetc_entry(stdin) != EOF || errno != 0) {
        status = 4;
        goto cleanup;
    }
    if (feof_entry(stdin) == 0 || feof_unlocked_entry(stdin) == 0)
        status = 5;

cleanup:
    if (restore_stdin(saved) != 0 && status == 0)
        status = 6;
    return status;
}

#ifndef CRABC_STDIO_PERMANENT_FEOF_UNLOCKED_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_feof_unlocked_probe();
}
#endif
