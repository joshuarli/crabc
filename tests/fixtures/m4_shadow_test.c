#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <shadow.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int fields_ok(const struct spwd *sp)
{
    return sp && sp->sp_namp && sp->sp_pwdp;
}

static int dates_equal(const struct spwd *left, const struct spwd *right)
{
    return left->sp_lstchg == right->sp_lstchg &&
        left->sp_min == right->sp_min && left->sp_max == right->sp_max &&
        left->sp_warn == right->sp_warn && left->sp_inact == right->sp_inact &&
        left->sp_expire == right->sp_expire && left->sp_flag == right->sp_flag;
}

int main(void)
{
    FILE *probe;
    struct spwd *first;
    struct spwd *direct;
    struct spwd output;
    struct spwd *result = (struct spwd *)1;
    char name[256];
    char buffer[4096];
    char tiny[1];
    int rc;
    unsigned int count = 0;
    FILE *stream;
    struct spwd controlled = {
        (char *)"crabc-shadow-roundtrip",
        (char *)"$6$crabc$hash",
        -12,
        -1,
        34,
        -56,
        -1,
        78,
        99,
    };

    /* The password lock is an actual cross-process advisory lock, not a
       success-only placeholder.  This runs inside the disposable Docker
       image, where the test runner owns /etc/.pwd.lock. */
    if (lckpwdf() != 0)
        return 1;
    errno = 0;
    if (lckpwdf() != -1 || errno != EBUSY)
        return 2;
    {
        pid_t child = fork();
        int status;
        if (child < 0)
            return 3;
        if (child == 0) {
            int fd = open("/etc/.pwd.lock", O_WRONLY);
            struct flock lock = { F_WRLCK, SEEK_SET, 0, 0, 0 };
            if (fd < 0)
                _exit(1);
            if (fcntl(fd, F_SETLK, &lock) != -1 ||
                (errno != EACCES && errno != EAGAIN))
                _exit(2);
            _exit(0);
        }
        if (waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            return 4;
    }
    if (ulckpwdf() != 0)
        return 5;
    errno = 0;
    if (ulckpwdf() != -1 || errno != EINVAL)
        return 6;

    stream = tmpfile();
    if (!stream || putspent(&controlled, stream) != 0)
        return 7;
    if (fputs("negative:x:-12::-3:+4:-5::\n", stream) < 0)
        return 8;
    rewind(stream);
    direct = fgetspent(stream);
    if (!fields_ok(direct) || strcmp(direct->sp_namp, controlled.sp_namp) != 0 ||
        strcmp(direct->sp_pwdp, controlled.sp_pwdp) != 0 ||
        !dates_equal(direct, &controlled))
        return 9;
    direct = fgetspent(stream);
    if (!fields_ok(direct) || strcmp(direct->sp_namp, "negative") != 0 ||
        direct->sp_lstchg != -12 || direct->sp_min != -1 ||
        direct->sp_max != -3 || direct->sp_warn != 4 ||
        direct->sp_inact != -5 || direct->sp_expire != -1 ||
        direct->sp_flag != ULONG_MAX)
        return 10;
    fclose(stream);

    errno = 0;
    probe = fopen("/etc/shadow", "r");
    if (!probe) {
        int source_errno = errno;
        errno = 0;
        if (getspent() || errno != source_errno)
            return 11;
        errno = 0;
        if (getspnam("root") || errno != source_errno)
            return 12;
        puts("m4 shadow ok");
        return 0;
    }
    fclose(probe);

    setspent();
    first = getspent();
    if (!fields_ok(first))
        return 13;
    strncpy(name, first->sp_namp, sizeof(name) - 1);
    name[sizeof(name) - 1] = 0;
    direct = getspnam(name);
    if (!fields_ok(direct) || strcmp(direct->sp_namp, name) != 0)
        return 14;

    result = (struct spwd *)1;
    rc = getspnam_r(name, &output, tiny, sizeof(tiny), &result);
    if (rc != ERANGE || result != NULL)
        return 15;
    result = (struct spwd *)1;
    rc = getspnam_r(name, &output, NULL, 0, &result);
    if (rc != ERANGE || result != NULL)
        return 16;
    result = (struct spwd *)1;
    rc = getspnam_r(name, &output, buffer, sizeof(buffer), &result);
    if (rc != 0 || result != &output || !fields_ok(result) ||
        strcmp(result->sp_namp, direct->sp_namp) != 0 ||
        strcmp(result->sp_pwdp, direct->sp_pwdp) != 0 ||
        !dates_equal(result, direct))
        return 17;
    result = (struct spwd *)1;
    rc = getspnam_r("crabc-shadow-that-does-not-exist", &output,
        buffer, sizeof(buffer), &result);
    if (rc != 0 || result != NULL)
        return 18;

    setspent();
    direct = getspent();
    if (!fields_ok(direct) || strcmp(direct->sp_namp, name) != 0)
        return 19;
    do {
        direct = getspent();
        if (direct && !fields_ok(direct))
            return 20;
        if (direct && ++count > 512)
            return 21;
    } while (direct);
    endspent();
    direct = getspent();
    if (!fields_ok(direct))
        return 22;
    endspent();

    puts("m4 shadow ok");
    return 0;
}
