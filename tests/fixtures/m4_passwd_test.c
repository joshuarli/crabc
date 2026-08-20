#define _GNU_SOURCE 1

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fields_ok(const struct passwd *pw)
{
    return pw && pw->pw_name && pw->pw_passwd && pw->pw_gecos &&
        pw->pw_dir && pw->pw_shell;
}

int main(void)
{
    uid_t uid = getuid();
    struct passwd *direct;
    struct passwd output;
    struct passwd *result = (struct passwd *)1;
    char name[256];
    char buffer[4096];
    char tiny[1];
    int rc;
    unsigned int count = 0;
    char first_name[256];
    uid_t first_uid;
    FILE *stream;
    struct passwd controlled = {
        (char *)"crabc-roundtrip",
        (char *)"x",
        1234,
        2345,
        (char *)"Crabc Test",
        (char *)"/home/crabc",
        (char *)"/bin/sh",
    };

    direct = getpwuid(uid);
    if (!fields_ok(direct) || direct->pw_uid != uid)
        return 1;
    strncpy(name, direct->pw_name, sizeof(name) - 1);
    name[sizeof(name) - 1] = 0;
    direct = getpwnam(name);
    if (!fields_ok(direct) || direct->pw_uid != uid || strcmp(direct->pw_name, name))
        return 2;

    result = (struct passwd *)1;
    rc = getpwuid_r(uid, &output, tiny, sizeof(tiny), &result);
    if (rc != ERANGE || result != NULL)
        return 3;
    result = (struct passwd *)1;
    rc = getpwuid_r(uid, &output, NULL, 0, &result);
    if (rc != ERANGE || result != NULL)
        return 4;
    result = (struct passwd *)1;
    rc = getpwuid_r(uid, &output, buffer, sizeof(buffer), &result);
    if (rc != 0 || result != &output || !fields_ok(result) || result->pw_uid != uid ||
        strcmp(result->pw_name, direct->pw_name) != 0 ||
        strcmp(result->pw_passwd, direct->pw_passwd) != 0 ||
        strcmp(result->pw_gecos, direct->pw_gecos) != 0 ||
        strcmp(result->pw_dir, direct->pw_dir) != 0 ||
        strcmp(result->pw_shell, direct->pw_shell) != 0)
        return 5;
    result = (struct passwd *)1;
    rc = getpwnam_r("crabc-account-that-does-not-exist", &output,
        buffer, sizeof(buffer), &result);
    if (rc != 0 || result != NULL)
        return 6;

    setpwent();
    direct = getpwent();
    if (!fields_ok(direct))
        return 7;
    strncpy(first_name, direct->pw_name, sizeof(first_name) - 1);
    first_name[sizeof(first_name) - 1] = 0;
    first_uid = direct->pw_uid;
    setpwent();
    direct = getpwent();
    if (!fields_ok(direct) || direct->pw_uid != first_uid ||
        strcmp(direct->pw_name, first_name))
        return 8;
    do {
        direct = getpwent();
        if (direct && !fields_ok(direct))
            return 9;
        if (direct && ++count > 512)
            return 10;
    } while (direct);
    endpwent();
    direct = getpwent();
    if (!fields_ok(direct))
        return 11;
    endpwent();

    stream = tmpfile();
    if (!stream || putpwent(&controlled, stream) != 0)
        return 12;
    rewind(stream);
    direct = fgetpwent(stream);
    if (!fields_ok(direct) || strcmp(direct->pw_name, controlled.pw_name) ||
        strcmp(direct->pw_passwd, controlled.pw_passwd) ||
        direct->pw_uid != controlled.pw_uid || direct->pw_gid != controlled.pw_gid ||
        strcmp(direct->pw_gecos, controlled.pw_gecos) ||
        strcmp(direct->pw_dir, controlled.pw_dir) ||
        strcmp(direct->pw_shell, controlled.pw_shell))
        return 13;
    fclose(stream);

    puts("m4 passwd ok");
    return 0;
}
