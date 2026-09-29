/* Static x86-64 secure_getenv and process-environment differential fixture. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <stdlib.h>

extern char **environ;

_Static_assert(sizeof(char *) == 8, "x86 LP64 pointer ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&secure_getenv),
    char *(*)(const char *)), "secure_getenv declaration");

#if defined(CRABC_SECURE_ENVIRONMENT_SYNTHETIC) && \
    !defined(CRABC_SECURE_ENVIRONMENT_SYNTHETIC_AT_SECURE_CLEARED)
#define EXPECT_SECURE 1
#else
#define EXPECT_SECURE 0
#endif

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

/* A raw write keeps the fixture's transcript independent of stdio selection. */
static void trace(const char *message)
{
    unsigned long length = 0;
    long result;
    while (message[length])
        ++length;
    __asm__ volatile("syscall" : "=a"(result) : "0"(1L), "D"(1L), "S"(message),
        "d"(length) : "rcx", "r11", "memory");
    (void)result;
}

static int check_lookup(const char *name, const char *expected)
{
    char *ordinary = getenv(name);
    char *secure;

    if (!same_text(ordinary, expected))
        return 1;
    errno = E2BIG;
    secure = secure_getenv(name);
    if (errno != E2BIG || (EXPECT_SECURE ? secure != 0 : secure != ordinary))
        return 2;
    return 0;
}

static int check_environment(void)
{
    char copied[] = "copied";
    char borrowed[] = "BORROW=one";
    char removal[] = "BORROW";
    char direct_entry[] = "DIRECT=external";
    char *direct[] = {direct_entry, 0};

    if (check_lookup("OPEN", "visible") || check_lookup("MISSING", 0))
        return 1;
    trace("initial\n");

    errno = E2BIG;
    if (getenv("") != 0 || secure_getenv("") != 0 || errno != E2BIG)
        return 2;
    errno = E2BIG;
    if (getenv("BAD=NAME") != 0 || secure_getenv("BAD=NAME") != 0 || errno != E2BIG)
        return 3;
    errno = E2BIG;
    if (setenv("", "x", 1) != -1 || errno != EINVAL)
        return 4;
    errno = E2BIG;
    if (setenv("BAD=NAME", "x", 1) != -1 || errno != EINVAL)
        return 5;
    errno = E2BIG;
    if (unsetenv("") != -1 || errno != EINVAL)
        return 6;
    trace("invalid-names\n");

    errno = E2BIG;
    if (setenv("OWN", copied, 1) != 0 || errno != E2BIG)
        return 7;
    copied[0] = 'X';
    if (check_lookup("OWN", "copied"))
        return 8;
    errno = E2BIG;
    if (setenv("OWN", "ignored", 0) != 0 || errno != E2BIG ||
        check_lookup("OWN", "copied"))
        return 9;
    errno = E2BIG;
    if (setenv("OWN", "replaced", 1) != 0 || errno != E2BIG ||
        check_lookup("OWN", "replaced"))
        return 10;
    trace("setenv-copy-replace\n");

    errno = E2BIG;
    if (putenv(borrowed) != 0 || errno != E2BIG ||
        check_lookup("BORROW", "one"))
        return 11;
    borrowed[7] = 't';
    if (check_lookup("BORROW", "tne"))
        return 12;
    errno = E2BIG;
    if (putenv(removal) != 0 || errno != E2BIG ||
        check_lookup("BORROW", 0))
        return 13;
    trace("putenv-borrow-remove\n");

    environ = direct;
    if (check_lookup("DIRECT", "external") || check_lookup("OWN", 0))
        return 14;
    errno = E2BIG;
    if (setenv("DIRECT", "later", 1) != 0 || errno != E2BIG ||
        check_lookup("DIRECT", "later"))
        return 15;
    trace("direct-environ\n");

    errno = E2BIG;
    if (unsetenv("DIRECT") != 0 || errno != E2BIG ||
        check_lookup("DIRECT", 0))
        return 16;
    errno = E2BIG;
    if (clearenv() != 0 || errno != E2BIG || environ != 0 ||
        check_lookup("OPEN", 0))
        return 17;
    trace("unsetenv-clearenv\n");

#if EXPECT_SECURE
    /* The secure gate returns before reading even an invalid name pointer. */
    errno = E2BIG;
    if (secure_getenv((const char *)1) != 0 || errno != E2BIG)
        return 18;
    trace("secure-invalid-pointer\n");
#endif
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    (void)argc;
    (void)argv;
    (void)envp;
    return check_environment();
}
