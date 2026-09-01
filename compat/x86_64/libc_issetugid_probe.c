/* Static Linux/x86-64 issetugid C ABI and behavior fixture.
 *
 * The same GNU project-header C body first executes through pinned musl 1.2.6
 * in an ordinary process, then through a true `-nostdlib -static` crabc
 * candidate. Candidate-only synthetic initial auxiliary vectors prove the
 * cached secure result for final AT_SECURE and UID/EUID mismatch. The fixture
 * selects no credential mutation, secure_getenv, environment lookup, or raw
 * auxiliary-vector C API.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <unistd.h>

_Static_assert(sizeof(int) == 4, "Linux/x86-64 int ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&issetugid),
    int (*)(void)), "issetugid declaration");

typedef int (*issetugid_signature)(void);

static int check_ordinary(void)
{
    const issetugid_signature function = issetugid;

    errno = E2BIG;
    if (issetugid() != 0 || errno != E2BIG)
        return 1;
    errno = E2BIG;
    if (function() != 0 || errno != E2BIG)
        return 2;
    return 0;
}

static int check_secure(void)
{
    const issetugid_signature function = issetugid;

    errno = E2BIG;
    if (issetugid() != 1 || errno != E2BIG)
        return 1;
    errno = E2BIG;
    if (function() != 1 || errno != E2BIG)
        return 2;
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    (void)argc;
    (void)argv;
    (void)envp;
#ifdef CRABC_ISSETUGID_SYNTHETIC
    return check_secure();
#else
    return check_ordinary();
#endif
}
