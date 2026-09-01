/* Static x86-64 permanent-standard-stream ferror_unlocked regression fixture.
 *
 * This project-header source first executes through pinned musl 1.2.6 and
 * then through one true -nostdlib/-static crabc archive. It calls only the
 * GNU/BSD `ferror_unlocked` alias and its strong `ferror` target on permanent
 * stdin. Closing that descriptor before existing fgetc is marker setup solely:
 * both predicates must transition from zero to nonzero. The source makes no
 * claim about musl's numeric `1` normalization, FLOCK/FUNLOCK, lock-free
 * behavior, general FILE state, another status alias, or byte-I/O beyond that
 * deterministic error marker.
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
typedef int (*status_predicate_fn)(FILE *);

static close_fn volatile close_entry = close;
static dup_fn volatile dup_entry = dup;
static dup2_fn volatile dup2_entry = dup2;
static fgetc_fn volatile fgetc_entry = fgetc;
static status_predicate_fn volatile ferror_entry = ferror;
static status_predicate_fn volatile ferror_unlocked_entry = ferror_unlocked;

static int restore_stdin(int saved)
{
    if (dup2_entry(saved, STDIN_FILENO) != STDIN_FILENO) {
        (void)close_entry(saved);
        return -1;
    }
    return close_entry(saved) == 0 ? 0 : -1;
}

int crabc_x86_64_stdio_permanent_ferror_unlocked_probe(void)
{
    int saved = -1;
    int status = 0;

    if (ferror_unlocked_entry != ferror_entry)
        return 1;
    saved = dup_entry(STDIN_FILENO);
    if (saved < 0)
        return 2;
    if (ferror_entry(stdin) != 0 || ferror_unlocked_entry(stdin) != 0) {
        status = 3;
        goto cleanup;
    }
    if (close_entry(STDIN_FILENO) != 0) {
        status = 4;
        goto cleanup;
    }
    errno = 0;
    if (fgetc_entry(stdin) != EOF || errno != EBADF) {
        status = 5;
        goto cleanup;
    }
    if (ferror_entry(stdin) == 0 || ferror_unlocked_entry(stdin) == 0)
        status = 6;

cleanup:
    if (restore_stdin(saved) != 0 && status == 0)
        status = 7;
    return status;
}

#ifndef CRABC_STDIO_PERMANENT_FERROR_UNLOCKED_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_ferror_unlocked_probe();
}
#endif
