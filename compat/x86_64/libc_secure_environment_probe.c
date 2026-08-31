/* Static x86-64 secure_getenv musl differential fixture. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <stdlib.h>

_Static_assert(sizeof(char *) == 8, "x86 LP64 pointer ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&secure_getenv),
    char *(*)(const char *)), "secure_getenv declaration");

static int same_text(const char *left, const char *right)
{
    if (left == 0 || right == 0)
        return left == right;
    while (*left != '\0' && *right != '\0') {
        if (*left != *right)
            return 0;
        ++left;
        ++right;
    }
    return *left == *right;
}

static int check_normal_environment(void)
{
    char *ordinary;
    char *secure;

    ordinary = getenv("OPEN");
    errno = E2BIG;
    secure = secure_getenv("OPEN");
    if (!same_text(ordinary, "visible") || secure != ordinary || errno != E2BIG)
        return 1;
    errno = E2BIG;
    if (secure_getenv("MISSING") != 0 || errno != E2BIG)
        return 2;
    return 0;
}

static int check_secure_environment(void)
{
    char *ordinary;

    ordinary = getenv("OPEN");
    if (!same_text(ordinary, "visible"))
        return 1;
    errno = E2BIG;
    if (secure_getenv("OPEN") != 0 || errno != E2BIG)
        return 2;
    errno = E2BIG;
    if (secure_getenv("MISSING") != 0 || errno != E2BIG)
        return 3;
    /* Secure mode must not inspect the name before returning null. */
    errno = E2BIG;
    if (secure_getenv((const char *)1) != 0 || errno != E2BIG)
        return 4;
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    (void)argc;
    (void)argv;
    (void)envp;
#ifdef CRABC_SECURE_ENVIRONMENT_SYNTHETIC
    return check_secure_environment();
#else
    return check_normal_environment();
#endif
}
