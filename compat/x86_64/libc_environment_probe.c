/* Static crabc-libc x86-64 bounded process-environment fixture.
 *
 * The same project-header C body first runs against pinned musl 1.2.6 and
 * then through a true `-nostdlib -static` executable linked only with the
 * selected crabc archive.  It proves the intentionally bounded C
 * getenv/setenv/putenv/unsetenv/clearenv and environ-alias boundary.  Its
 * fixed test vectors are fixture storage, not an allocator or a claim for a
 * general process-environment lifecycle, secure execution, exec/spawn, or
 * thread-safe environment mutation.
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
#include <stdlib.h>
#include <unistd.h>

extern char **__environ;
extern char **_environ;
extern char **___environ;

#define CRABC_TYPE_IS(expression, type) \
    __builtin_types_compatible_p(__typeof__(expression), type)

typedef char *(*getenv_signature)(const char *);
typedef int (*setenv_signature)(const char *, const char *, int);
typedef int (*putenv_signature)(char *);
typedef int (*unsetenv_signature)(const char *);
typedef int (*clearenv_signature)(void);

_Static_assert(CRABC_TYPE_IS(&getenv, getenv_signature),
    "getenv declaration");
_Static_assert(CRABC_TYPE_IS(&setenv, setenv_signature),
    "setenv declaration");
_Static_assert(CRABC_TYPE_IS(&putenv, putenv_signature),
    "putenv declaration");
_Static_assert(CRABC_TYPE_IS(&unsetenv, unsetenv_signature),
    "unsetenv declaration");
_Static_assert(CRABC_TYPE_IS(&clearenv, clearenv_signature),
    "clearenv declaration");
_Static_assert(CRABC_TYPE_IS(environ, char **),
    "GNU environ declaration");
_Static_assert(sizeof(char *) == 8 && _Alignof(char *) == 8,
    "x86 LP64 environment pointer ABI");

enum {
    ENVIRONMENT_ENTRY_CAPACITY = 128,
    ENVIRONMENT_STORAGE_BYTES = 16 * 1024,
    ENVIRONMENT_LOOKUP_LIMIT = 1 << 20,
};

static int same_text(const char *left, const char *right)
{
    size_t index = 0;

    if (left == NULL || right == NULL)
        return left == right;
    for (;;) {
        if (left[index] != right[index])
            return 0;
        if (left[index] == '\0')
            return 1;
        ++index;
    }
}

static int aliases_match(char **expected)
{
    return &environ == &__environ && &environ == &_environ &&
        &environ == &___environ && environ == expected &&
        __environ == expected && _environ == expected &&
        ___environ == expected;
}

static int check_startup_environment(int argc, char **argv, char **envp)
{
    if (argc != 1 || argv == NULL || argv[0] == NULL || argv[1] != NULL)
        return 1;
    if (envp == NULL || envp[0] == NULL || envp[1] != NULL)
        return 2;
    if (!aliases_match(envp))
        return 3;
    if (!same_text(envp[0], "CRABC_X86_INITIAL=entry") ||
        !same_text(getenv("CRABC_X86_INITIAL"), "entry"))
        return 4;
    return 0;
}

static int check_initial_and_mutation(void)
{
    static char base[] = "BASE=initial";
    static char duplicate_first[] = "DUP=first";
    static char duplicate_second[] = "DUP=second";
    static char beta[] = "BETA=initial";
    static char *initial[] = {
        base,
        duplicate_first,
        duplicate_second,
        beta,
        NULL,
    };
    char remove_duplicate[] = "DUP";
    char copied_value[] = "copied";
    char borrowed[] = "BORROW=borrowed";

    __environ = initial;
    if (!aliases_match(initial))
        return 1;
    if (!same_text(getenv("BASE"), "initial") ||
        !same_text(getenv("DUP"), "first"))
        return 2;

    if (putenv(remove_duplicate) != 0 || getenv("DUP") != NULL)
        return 3;
    if (!aliases_match(environ))
        return 4;

    errno = EINTR;
    if (setenv("BETA", "ignored", 0) != 0 ||
        !same_text(getenv("BETA"), "initial") || errno != EINTR)
        return 5;
    if (setenv("BETA", copied_value, 1) != 0)
        return 6;
    copied_value[0] = 'X';
    if (!same_text(getenv("BETA"), "copied"))
        return 7;

    if (putenv(borrowed) != 0 || !same_text(getenv("BORROW"), "borrowed"))
        return 8;
    borrowed[7] = 'B';
    if (!same_text(getenv("BORROW"), "Borrowed"))
        return 9;

    errno = 0;
    if (setenv("", "value", 1) != -1 || errno != EINVAL)
        return 10;
    errno = 0;
    if (setenv("BAD=NAME", "value", 1) != -1 || errno != EINVAL)
        return 11;
    errno = 0;
    if (unsetenv("") != -1 || errno != EINVAL)
        return 12;
    errno = 0;
    if (unsetenv("BAD=NAME") != -1 || errno != EINVAL)
        return 13;
    errno = 0;
    if (putenv("=") != -1 || errno != EINVAL)
        return 14;
    return 0;
}

static int check_clear_and_direct_assignment(void)
{
    static char direct[] = "DIRECT=visible";
    static char *direct_environment[] = { direct, NULL };

    errno = EINTR;
    if (clearenv() != 0 || !aliases_match(NULL) || getenv("BETA") != NULL ||
        errno != EINTR)
        return 1;
    if (setenv("AFTER", "clear", 1) != 0 ||
        !same_text(getenv("AFTER"), "clear") || environ == NULL)
        return 2;

    environ = direct_environment;
    if (!aliases_match(direct_environment) ||
        !same_text(getenv("DIRECT"), "visible"))
        return 3;
    if (setenv("DIRECT", "copied", 1) != 0 ||
        !same_text(getenv("DIRECT"), "copied") || !aliases_match(environ))
        return 4;
    return 0;
}

static int check_fixed_capacity(void)
{
    static char entries[ENVIRONMENT_ENTRY_CAPACITY][16];
    static char *full_environment[ENVIRONMENT_ENTRY_CAPACITY + 1];
    static char overflow[] = "OVERFLOW=v";
    static char *overfull_environment[ENVIRONMENT_ENTRY_CAPACITY + 2];
    char **materialized_environment;
    size_t index;

    if (clearenv() != 0)
        return 1;
    for (index = 0; index < ENVIRONMENT_ENTRY_CAPACITY; ++index) {
        char *entry = entries[index];

        entry[0] = 'E';
        entry[1] = (char)('0' + (index / 100));
        entry[2] = (char)('0' + ((index / 10) % 10));
        entry[3] = (char)('0' + (index % 10));
        entry[4] = '=';
        entry[5] = 'v';
        entry[6] = '\0';
        full_environment[index] = entry;
        overfull_environment[index] = entry;
    }
    full_environment[ENVIRONMENT_ENTRY_CAPACITY] = NULL;
    overfull_environment[ENVIRONMENT_ENTRY_CAPACITY] = overflow;
    overfull_environment[ENVIRONMENT_ENTRY_CAPACITY + 1] = NULL;
    environ = full_environment;

    if (setenv("E127", "replacement", 1) != 0 ||
        !same_text(getenv("E127"), "replacement"))
        return 2;
    materialized_environment = environ;
    errno = 0;
    if (setenv("EXTRA", "value", 1) != -1 || errno != ENOMEM ||
        !aliases_match(materialized_environment) || getenv("EXTRA") != NULL ||
        !same_text(getenv("E127"), "replacement"))
        return 3;

    environ = overfull_environment;
    errno = 0;
    if (unsetenv("E127") != -1 || errno != ENOMEM ||
        !aliases_match(overfull_environment) ||
        !same_text(getenv("E127"), "v"))
        return 4;
    errno = EINTR;
    if (clearenv() != 0 || !aliases_match(NULL) || errno != EINTR)
        return 5;
    return 0;
}

static int check_fixed_storage(void)
{
    static char too_large[ENVIRONMENT_STORAGE_BYTES];
    size_t index;

    if (clearenv() != 0 || setenv("SAFE", "unchanged", 1) != 0)
        return 1;
    for (index = 0; index + 1 < sizeof(too_large); ++index)
        too_large[index] = 'x';
    too_large[sizeof(too_large) - 1] = '\0';

    errno = 0;
    if (setenv("TOO_LARGE", too_large, 1) != -1 || errno != ENOMEM ||
        !same_text(getenv("SAFE"), "unchanged") ||
        getenv("TOO_LARGE") != NULL)
        return 2;
    return 0;
}

static int check_nonreclaiming_storage(void)
{
    size_t successful_replacements = 0;

    errno = 0;
    while (successful_replacements < ENVIRONMENT_STORAGE_BYTES &&
        setenv("X", "", 1) == 0)
        ++successful_replacements;
    if (successful_replacements == 0 ||
        successful_replacements == ENVIRONMENT_STORAGE_BYTES ||
        errno != ENOMEM || !same_text(getenv("X"), ""))
        return 1;
    if (unsetenv("X") != 0 || clearenv() != 0 || environ != NULL)
        return 2;

    /* Removed and cleared setenv strings deliberately remain arena-owned. */
    errno = 0;
    if (setenv("Y", "", 1) != -1 || errno != ENOMEM ||
        getenv("Y") != NULL || environ != NULL)
        return 3;
    return 0;
}

static int check_lookup_limit(void)
{
    static char filler[] = "FILL=v";
    static char beyond[] = "BEYOND=visible";
    static char *lookup_limit_environment[ENVIRONMENT_LOOKUP_LIMIT + 2];
    size_t index;

    for (index = 0; index < ENVIRONMENT_LOOKUP_LIMIT; ++index)
        lookup_limit_environment[index] = filler;
    lookup_limit_environment[ENVIRONMENT_LOOKUP_LIMIT] = beyond;
    lookup_limit_environment[ENVIRONMENT_LOOKUP_LIMIT + 1] = NULL;
    environ = lookup_limit_environment;

    errno = EINTR;
    if (!same_text(getenv("FILL"), "v") || getenv("BEYOND") != NULL ||
        !aliases_match(lookup_limit_environment) || errno != EINTR)
        return 1;
    if (clearenv() != 0 || !aliases_match(NULL) || errno != EINTR)
        return 2;
    return 0;
}

int crabc_x86_64_environment_probe(int argc, char **argv, char **envp)
{
    int status;

    status = check_startup_environment(argc, argv, envp);
    if (status != 0)
        return status;
    status = check_initial_and_mutation();
    if (status != 0)
        return 10 + status;
    status = check_clear_and_direct_assignment();
    if (status != 0)
        return 30 + status;
#ifdef CRABC_ENVIRONMENT_FREESTANDING
    /*
     * Musl allocates its pointer vector and replacement strings, while this
     * no-allocator archive deliberately publishes the documented 128-entry
     * and 16-KiB ENOMEM boundaries. These are candidate-only tests rather
     * than a false claim that musl has the same resource limits.
     */
    status = check_fixed_capacity();
    if (status != 0)
        return 40 + status;
    status = check_fixed_storage();
    if (status != 0)
        return 50 + status;
    status = check_lookup_limit();
    if (status != 0)
        return 60 + status;
    status = check_nonreclaiming_storage();
    if (status != 0)
        return 70 + status;
#endif
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    return crabc_x86_64_environment_probe(argc, argv, envp);
}
