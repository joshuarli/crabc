#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <utmp.h>
#include <utmpx.h>

static void fill_record(struct utmpx *record, short type, const char *id,
    const char *line, const char *user)
{
    memset(record, 0, sizeof(*record));
    record->ut_type = type;
    record->ut_pid = getpid();
    memcpy(record->ut_id, id, strlen(id) < sizeof(record->ut_id) ?
        strlen(id) : sizeof(record->ut_id));
    memcpy(record->ut_line, line, strlen(line) < sizeof(record->ut_line) ?
        strlen(line) : sizeof(record->ut_line));
    memcpy(record->ut_user, user, strlen(user) < sizeof(record->ut_user) ?
        strlen(user) : sizeof(record->ut_user));
}

static int read_full(int fd, void *buffer, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t result = read(fd, (char *)buffer + offset, size - offset);
        if (result <= 0)
            return -1;
        offset += (size_t)result;
    }
    return 0;
}

int main(void)
{
    char database[128];
    char wtmp[128];
    struct utmpx first;
    struct utmpx second;
    struct utmpx third;
    struct utmpx *got;
    int fd;

    snprintf(database, sizeof(database), "/tmp/crabc-utmp-%ld.db",
        (long)getpid());
    snprintf(wtmp, sizeof(wtmp), "/tmp/crabc-wtmp-%ld.db", (long)getpid());
    unlink(database);
    unlink(wtmp);

    fill_record(&first, USER_PROCESS, "aa", "ttyA", "alice");
    fill_record(&second, LOGIN_PROCESS, "bb", "ttyB", "bob");
    fill_record(&third, DEAD_PROCESS, "cc", "ttyC", "carol");

    if (utmpxname(database) != 0)
        return 1;
    if (!pututxline(&first) || !pututxline(&second) || !pututxline(&third))
        return 2;

    /* The traditional API names share the selected database and cursor. */
    if (utmpname(database) != 0)
        return 3;
    setutent();
    got = getutent();
    if (!got || got->ut_type != USER_PROCESS ||
        memcmp(got->ut_id, first.ut_id, sizeof(got->ut_id)) != 0)
        return 4;
    endutent();

    setutxent();
    got = getutxent();
    if (!got || got->ut_type != USER_PROCESS)
        return 5;
    got = getutxent();
    if (!got || got->ut_type != LOGIN_PROCESS)
        return 6;
    got = getutxent();
    if (!got || got->ut_type != DEAD_PROCESS)
        return 7;
    if (getutxent() != NULL)
        return 8;

    setutxent();
    got = getutxid(&second);
    if (!got || memcmp(got->ut_id, second.ut_id, sizeof(got->ut_id)) != 0)
        return 9;
    setutxent();
    got = getutxline(&second);
    if (!got || memcmp(got->ut_id, second.ut_id, sizeof(got->ut_id)) != 0)
        return 10;

    memcpy(second.ut_user, "updated", sizeof("updated") - 1);
    got = pututxline(&second);
    if (!got)
        return 11;
    setutxent();
    got = getutxid(&second);
    if (!got || memcmp(got->ut_user, "updated", sizeof("updated") - 1) != 0)
        return 12;

    /* Both wtmp spellings append complete records without touching utmp. */
    updwtmpx(wtmp, &first);
    updwtmp(wtmp, &second);
    fd = open(wtmp, O_RDONLY);
    if (fd < 0)
        return 13;
    if (read_full(fd, &first, sizeof(first)) != 0 ||
        read_full(fd, &third, sizeof(third)) != 0 ||
        memcmp(first.ut_id, "aa", 2) != 0 ||
        memcmp(third.ut_id, "bb", 2) != 0)
        return 14;
    if (read(fd, &third, sizeof(third)) != 0)
        return 15;
    close(fd);
    endutxent();
    unlink(database);
    unlink(wtmp);
    puts("c-abi utmp databases ok");
    return 0;
}
