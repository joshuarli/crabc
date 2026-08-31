/* Static crabc-libc x86-64 environment-backed login-name differential. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

extern char **environ;

_Static_assert(sizeof(size_t) == 8 && sizeof(char *) == 8,
    "x86 pointer and size ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getlogin),
    char *(*)(void)), "getlogin declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getlogin_r),
    int (*)(char *, size_t)), "getlogin_r declaration");

static void fill_bytes(char *bytes, unsigned long size, unsigned char value)
{
    unsigned long index;
    for (index = 0; index < size; ++index)
        bytes[index] = (char)value;
}

static int bytes_have_value(const char *bytes, unsigned long size,
                            unsigned char value)
{
    unsigned long index;
    for (index = 0; index < size; ++index)
        if ((unsigned char)bytes[index] != value)
            return 0;
    return 1;
}

static int bytes_equal(const char *left, const char *right,
                       unsigned long size)
{
    unsigned long index;
    for (index = 0; index < size; ++index)
        if (left[index] != right[index])
            return 0;
    return 1;
}

static int check_absent_logname(void)
{
    char buffer[8];

    if (clearenv() != 0)
        return 1;
    errno = E2BIG;
    if (getlogin() != 0 || errno != E2BIG)
        return 2;
    fill_bytes(buffer, sizeof(buffer), 0x5a);
    errno = E2BIG;
    if (getlogin_r(buffer, sizeof(buffer)) != ENXIO || errno != E2BIG ||
        !bytes_have_value(buffer, sizeof(buffer), 0x5a))
        return 3;
    errno = E2BIG;
    if (getlogin_r(0, 0) != ENXIO || errno != E2BIG)
        return 4;
    return 0;
}

static int check_borrowed_putenv_value(void)
{
    char borrowed[] = "LOGNAME=alpha";
    char buffer[8];

    if (clearenv() != 0 || putenv(borrowed) != 0)
        return 1;
    errno = E2BIG;
    if (getlogin() != borrowed + 8 || errno != E2BIG)
        return 2;
    borrowed[8] = 'A';
    if (getlogin() != borrowed + 8)
        return 3;
    fill_bytes(buffer, sizeof(buffer), 0x6b);
    errno = E2BIG;
    if (getlogin_r(buffer, 5) != ERANGE || errno != E2BIG ||
        !bytes_have_value(buffer, sizeof(buffer), 0x6b))
        return 4;
    errno = E2BIG;
    if (getlogin_r(buffer, 6) != 0 || errno != E2BIG ||
        !bytes_equal(buffer, "Alpha", 6) || (unsigned char)buffer[6] != 0x6b)
        return 5;
    return clearenv() == 0 ? 0 : 6;
}

static int check_first_match_and_copy(void)
{
    char first[] = "LOGNAME=first";
    char other[] = "OTHER=value";
    char second[] = "LOGNAME=second";
    char *duplicate_environment[] = { first, other, second, 0 };
    char buffer[8];
    int result = 1;

    environ = duplicate_environment;
    if (getlogin() != first + 8)
        goto cleanup;
    fill_bytes(buffer, sizeof(buffer), 0x3c);
    errno = E2BIG;
    if (getlogin_r(buffer, sizeof(buffer)) != 0 || errno != E2BIG ||
        !bytes_equal(buffer, "first", 6) || (unsigned char)buffer[6] != 0x3c)
        goto cleanup;
    result = 0;

cleanup:
    if (clearenv() != 0)
        result = 2;
    return result;
}

static int check_empty_logname(void)
{
    char empty[] = "LOGNAME=";
    char buffer[2];

    if (putenv(empty) != 0 || getlogin() != empty + 8 || *getlogin() != 0)
        return 1;
    fill_bytes(buffer, sizeof(buffer), 0x7d);
    errno = E2BIG;
    if (getlogin_r(0, 0) != ERANGE || errno != E2BIG)
        return 2;
    if (getlogin_r(buffer, 1) != 0 || errno != E2BIG || buffer[0] != 0 ||
        (unsigned char)buffer[1] != 0x7d)
        return 3;
    return clearenv() == 0 ? 0 : 4;
}

int crabc_x86_64_login_name_probe(void)
{
    int status = check_absent_logname();
    if (status != 0)
        return 10 + status;
    status = check_borrowed_putenv_value();
    if (status != 0)
        return 20 + status;
    status = check_first_match_and_copy();
    if (status != 0)
        return 30 + status;
    status = check_empty_logname();
    return status == 0 ? 0 : 40 + status;
}

#ifndef CRABC_LOGIN_NAME_FREESTANDING
int main(void)
{
    return crabc_x86_64_login_name_probe();
}
#endif
