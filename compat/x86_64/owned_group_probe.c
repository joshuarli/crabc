#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        dprintf(2, "owned-group line %d errno %d\n", __LINE__, errno); \
        _exit(77); \
    } \
} while (0)

static const char records[] =
    "malformed\n"
    "team:x:10:alice,bob\n"
    "empty:*:11:\n"
    "dupe:x:10:alice,alice\n"
    "wrap:x:4294967297:alice\n"
    "crlf:x:12:carol\r\n"
    "raw\xff:x:13:\xffuser\n"
    "tail:x:14:zed";

static void write_records(const char *text, size_t length)
{
    int descriptor;

    endgrent();
    descriptor = open("/etc/group", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(descriptor >= 0);
    CHECK(write(descriptor, text, length) == (ssize_t)length);
    CHECK(close(descriptor) == 0);
}

static void setup(void)
{
    write_records(records, sizeof(records) - 1);
}

static void group_in_buffer(const struct group *group, char *buffer, size_t capacity)
{
    size_t member;

    CHECK(group->gr_name >= buffer && group->gr_name < buffer + capacity);
    CHECK(group->gr_passwd >= buffer && group->gr_passwd < buffer + capacity);
    CHECK(group->gr_mem >= (char **)buffer && group->gr_mem < (char **)(buffer + capacity));
    CHECK(memchr(group->gr_name, 0, buffer + capacity - group->gr_name));
    CHECK(memchr(group->gr_passwd, 0, buffer + capacity - group->gr_passwd));
    for (member = 0; group->gr_mem[member]; member++) {
        CHECK(group->gr_mem[member] >= buffer && group->gr_mem[member] < buffer + capacity);
        CHECK(memchr(group->gr_mem[member], 0, buffer + capacity - group->gr_mem[member]));
    }
}

static void lookup(void)
{
    struct group group;
    struct group *result;
    char buffer[4096];

    setup();
    errno = EDOM;
    CHECK(getgrnam_r("team", &group, buffer, sizeof(buffer), &result) == 0);
    CHECK(result == &group && group.gr_gid == 10 && !strcmp(group.gr_passwd, "x"));
    CHECK(!strcmp(group.gr_mem[0], "alice") && !strcmp(group.gr_mem[1], "bob"));
    CHECK(!group.gr_mem[2] && errno == EDOM);
    group_in_buffer(&group, buffer, sizeof(buffer));

    CHECK(getgrgid_r(1, &group, buffer, sizeof(buffer), &result) == 0);
    CHECK(result == &group && !strcmp(group.gr_name, "wrap") && group.gr_gid == 1);
    CHECK(getgrnam_r("raw\xff", &group, buffer, sizeof(buffer), &result) == 0);
    CHECK(result == &group && !strcmp(group.gr_mem[0], "\xffuser"));
    CHECK(getgrgid_r(12, &group, buffer, sizeof(buffer), &result) == 0);
    CHECK(result == &group && !strcmp(group.gr_mem[0], "carol\r"));

    memset(buffer, 0x5a, sizeof(buffer));
    result = (void *)1;
    errno = EDOM;
    CHECK(getgrnam_r("absent", &group, buffer, sizeof(buffer), &result) == 0);
    CHECK(!result && errno == EDOM);
    for (size_t index = 0; index < sizeof(buffer); index++) {
        CHECK(buffer[index] == 0x5a);
    }
    CHECK(!getgrgid(9999));
}

static void ranges(void)
{
    FILE *stream;
    char *line = 0;
    size_t line_capacity = 0;
    size_t required;
    struct group group;
    struct group *result;
    char buffer[4096];

    setup();
    stream = fopen("/etc/group", "r");
    CHECK(stream);
    CHECK(getline(&line, &line_capacity, stream) > 0);
    CHECK(getline(&line, &line_capacity, stream) > 0);
    CHECK(fclose(stream) == 0);
    required = line_capacity + 3 * sizeof(char *) + 32;
    CHECK(required < sizeof(buffer));
    memset(buffer, 0x5a, sizeof(buffer));
    errno = 0;
    CHECK(getgrnam_r("team", &group, buffer, required - 1, &result) == ERANGE);
    CHECK(!result && errno == ERANGE);
    for (size_t index = 0; index < sizeof(buffer); index++) {
        CHECK(buffer[index] == 0x5a);
    }
    CHECK(getgrnam_r("team", &group, buffer, required, &result) == 0 && result == &group);
    group_in_buffer(&group, buffer, required);
    printf("matching allocation capacity %zu\n", line_capacity);
    free(line);

    {
        char large[3000];
        const char final[] = "last:x:21:alice\n";

        memset(large, 'x', sizeof(large));
        large[2500] = '\n';
        memcpy(large + 2501, final, sizeof(final) - 1);
        write_records(large, 2501 + sizeof(final) - 1);
        CHECK(getgrnam_r("last", &group, buffer, 128, &result) == ERANGE && !result);
        CHECK(getgrnam_r("last", &group, buffer, sizeof(buffer), &result) == 0);
        CHECK(result && group.gr_gid == 21);
    }
}

static void enumeration(void)
{
    struct group *first;
    struct group *lookup_result;
    FILE *stream;
    int descriptor_count = 0;
    unsigned remaining = 0;
    void (*volatile reset)(void) = setgrent;
    void (*volatile finish)(void) = endgrent;

    setup();
    CHECK(reset == finish);
    first = getgrent();
    CHECK(first && !strcmp(first->gr_name, "team"));
    for (int descriptor = 3; descriptor < 64; descriptor++) {
        int flags = fcntl(descriptor, F_GETFD);
        if (flags >= 0) {
            CHECK(flags & FD_CLOEXEC);
            descriptor_count++;
        }
    }
    CHECK(descriptor_count == 1);
    lookup_result = getgrnam("wrap");
    CHECK(lookup_result == first && lookup_result->gr_gid == 1);
    CHECK(getgrent() == first && !strcmp(first->gr_name, "empty"));

    stream = fopen("/etc/group", "r");
    CHECK(stream);
    lookup_result = fgetgrent(stream);
    CHECK(lookup_result && lookup_result != first && !strcmp(lookup_result->gr_name, "team"));
    CHECK(fgetgrent(stream) == lookup_result && !strcmp(lookup_result->gr_name, "empty"));
    CHECK(fclose(stream) == 0);

    endgrent();
    CHECK(getgrent() == first && !strcmp(first->gr_name, "team"));
    while (getgrent()) {
        remaining++;
    }
    CHECK(remaining == 6);
    CHECK(!getgrent());
    setgrent();
    CHECK(getgrent() == first && first->gr_gid == 10);
    endgrent();
}

static void stream(void)
{
    char bytes[] = "bad\none:x:1:a,b\ntwo:x:3:c";
    FILE *input = fmemopen(bytes, sizeof(bytes) - 1, "r");
    struct group *group;

    CHECK(input);
    group = fgetgrent(input);
    CHECK(group && !strcmp(group->gr_name, "one") && !strcmp(group->gr_mem[1], "b"));
    CHECK(fgetgrent(input) == group && !strcmp(group->gr_name, "two"));
    errno = EDOM;
    CHECK(!fgetgrent(input) && feof(input) && !ferror(input) && errno == EDOM);
    CHECK(fclose(input) == 0);

    input = fopen("/etc/group", "r");
    CHECK(input && close(fileno(input)) == 0);
    errno = 0;
    CHECK(!fgetgrent(input) && ferror(input) && errno == EBADF);
    CHECK(fclose(input) == -1);
}

static void output(void)
{
    char bytes[512] = {0};
    char *members[] = {"alice", "b,ob", 0};
    struct group group = {"n:x", "*", 4294967295U, members};
    FILE *stream = fmemopen(bytes, sizeof(bytes), "w+");

    CHECK(stream);
    CHECK(putgrent(&group, stream) == 0 && fflush(stream) == 0);
    CHECK(!strcmp(bytes, "n:x:*:4294967295:alice,b,ob\n"));
    CHECK(fclose(stream) == 0);

    group.gr_mem = 0;
    stream = fmemopen(bytes, sizeof(bytes), "w+");
    CHECK(stream && putgrent(&group, stream) == 0 && fflush(stream) == 0);
    CHECK(!strcmp(bytes, "n:x:*:4294967295:\n"));
    CHECK(fclose(stream) == 0);

    stream = fopen("/etc/group", "w");
    CHECK(stream && setvbuf(stream, 0, _IONBF, 0) == 0 && close(fileno(stream)) == 0);
    errno = 0;
    CHECK(putgrent(&group, stream) == -1 && errno == EBADF && ferror(stream));
    CHECK(fclose(stream) == -1);
}

static void memberships(void)
{
    gid_t groups[8] = {0};
    int count;

    setup();
    count = 8;
    errno = EDOM;
    CHECK(getgrouplist("alice", 7, groups, &count) == 4 && count == 4 && errno == EDOM);
    CHECK(groups[0] == 7 && groups[1] == 10 && groups[2] == 10 && groups[3] == 1);

    memset(groups, 0x5a, sizeof(groups));
    count = 2;
    errno = EDOM;
    CHECK(getgrouplist("alice", 7, groups, &count) == -1 && count == 4 && errno == EDOM);
    CHECK(groups[0] == 7 && groups[1] == 10);

    count = 0;
    errno = EDOM;
    CHECK(getgrouplist("alice", 7, groups, &count) == -1 && count == 4 && errno == EDOM);
    count = 8;
    CHECK(getgrouplist("nobody", 9, groups, &count) == 1 && count == 1 && groups[0] == 9);
}

static void memberships_without_local_group(const char *which)
{
    gid_t groups[4] = {0};
    int count = 4;
    int expected_errno;

    setup();
    if (!strcmp(which, "memberships-missing")) {
        CHECK(unlink("/etc/group") == 0);
        expected_errno = ENOENT;
    } else {
        CHECK(!strcmp(which, "memberships-not-directory"));
        CHECK(rename("/etc", "/saved-etc") == 0);
        {
            int descriptor = open("/etc", O_WRONLY | O_CREAT, 0600);
            CHECK(descriptor >= 0 && !close(descriptor));
        }
        expected_errno = ENOTDIR;
    }

    errno = EDOM;
    CHECK(getgrouplist("alice", 7, groups, &count) == 1);
    CHECK(count == 1 && groups[0] == 7 && errno == expected_errno);

    if (!strcmp(which, "memberships-not-directory")) {
        CHECK(unlink("/etc") == 0 && rename("/saved-etc", "/etc") == 0);
    }
}

static void initgroups_isolated(void)
{
    pid_t child;
    int status;

    setup();
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        gid_t groups[8] = {0};
        int count;

        CHECK(initgroups("alice", 7) == 0);
        count = getgroups((int)(sizeof(groups) / sizeof(*groups)), groups);
        CHECK(count == 4);
        {
            int primary = 0;
            int duplicate = 0;
            int wrapped = 0;

            // Linux stores the setgroups input in kernel order. The source
            // list is file ordered, but this post-syscall observation need
            // only prove the exact multiset handed to the credential boundary.
            for (int index = 0; index < count; index++) {
                primary += groups[index] == 7;
                duplicate += groups[index] == 10;
                wrapped += groups[index] == 1;
            }
            CHECK(primary == 1 && duplicate == 2 && wrapped == 1);
        }
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && !WEXITSTATUS(status));
}

static void filter(int number, unsigned action)
{
    struct instruction {
        unsigned short code;
        unsigned char yes;
        unsigned char no;
        unsigned value;
    };
    struct program {
        unsigned short count;
        struct instruction *instructions;
    };
    struct instruction instructions[] = {
        {0x20, 0, 0, 0},
        {0x15, 0, 1, (unsigned)number},
        {0x06, 0, 0, action},
        {0x06, 0, 0, 0x7fff0000},
    };
    struct program program = {4, instructions};

    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(syscall(SYS_seccomp, 1, 0, &program) == 0);
}

static void errors(const char *which)
{
    struct group group;
    struct group *result = (void *)1;
    char buffer[4096];
    int expected;

    setup();
    if (!strcmp(which, "missing")) {
        CHECK(unlink("/etc/group") == 0);
        expected = ENOENT;
    } else if (!strcmp(which, "directory")) {
        CHECK(unlink("/etc/group") == 0);
        CHECK(mkdir("/etc/group", 0700) == 0);
        expected = EISDIR;
    } else if (!strcmp(which, "not-directory")) {
        CHECK(rename("/etc", "/saved-etc") == 0);
        {
            int descriptor = open("/etc", O_WRONLY | O_CREAT, 0600);
            CHECK(descriptor >= 0 && !close(descriptor));
        }
        expected = ENOTDIR;
    } else if (!strcmp(which, "read-error")) {
        filter(SYS_read, 0x00050000 | EIO);
        expected = EIO;
    } else {
        filter(SYS_open, 0x00050000 | EACCES);
        filter(SYS_openat, 0x00050000 | EACCES);
        expected = EACCES;
    }

    memset(buffer, 0x5a, sizeof(buffer));
    errno = 0;
    CHECK(getgrnam_r("team", &group, buffer, sizeof(buffer), &result) == expected);
    CHECK(!result && errno == expected);
    for (size_t index = 0; index < sizeof(buffer); index++) {
        CHECK(buffer[index] == 0x5a);
    }
    if (!strcmp(which, "directory")) {
        CHECK(rmdir("/etc/group") == 0);
    }
    if (!strcmp(which, "not-directory")) {
        CHECK(unlink("/etc") == 0 && rename("/saved-etc", "/etc") == 0);
    }
}

static void local_only(int oracle)
{
    pid_t child;
    int status;

    setup();
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct group group;
        struct group *result;
        gid_t groups[8];
        int count = 8;
        char buffer[256];

        filter(SYS_socket, 0x80000000);
        CHECK(getgrnam_r("absent", &group, buffer, sizeof(buffer), &result) == 0 && !result);
        CHECK(getgrouplist("alice", 7, groups, &count) == 4 && count == 4);
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child);
    if (oracle) {
        CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS);
    } else {
        CHECK(WIFEXITED(status) && !WEXITSTATUS(status));
    }
}

static void *thread_lookup(void *argument)
{
    const char *name = argument;
    unsigned expected = !strcmp(name, "team") ? 10 : 11;
    struct group group;
    struct group *result;
    char buffer[4096];

    for (unsigned iteration = 0; iteration < 100; iteration++) {
        CHECK(getgrnam_r(name, &group, buffer, sizeof(buffer), &result) == 0);
        CHECK(result && group.gr_gid == expected);
        group_in_buffer(&group, buffer, sizeof(buffer));
    }
    return 0;
}

static void threads(void)
{
    pthread_t first;
    pthread_t second;

    setup();
    CHECK(!pthread_create(&first, 0, thread_lookup, "team"));
    CHECK(!pthread_create(&second, 0, thread_lookup, "empty"));
    CHECK(!pthread_join(first, 0) && !pthread_join(second, 0));
}

static void fork_cursor(void)
{
    pid_t child;
    int status;

    setup();
    CHECK(getgrent()->gr_gid == 10);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(getgrent()->gr_gid == 11);
        setgrent();
        CHECK(getgrent()->gr_gid == 10);
        endgrent();
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(getgrent()->gr_gid == 11);
    endgrent();
}

static volatile int cancellation_returned;

static void *cancel_lookup(void *unused)
{
    struct group group;
    struct group *result;
    char buffer[4096];

    (void)unused;
    CHECK(pthread_cancel(pthread_self()) == 0);
    CHECK(getgrnam_r("team", &group, buffer, sizeof(buffer), &result) == 0 && result);
    CHECK(getgrgid(11));
    CHECK(getgrent());
    endgrent();
    cancellation_returned = 1;
    pthread_testcancel();
    _exit(78);
}

static void cancellation(void)
{
    pthread_t thread;
    void *result;

    setup();
    CHECK(!pthread_create(&thread, 0, cancel_lookup, 0));
    CHECK(!pthread_join(thread, &result) && result == PTHREAD_CANCELED && cancellation_returned);
}

static void allocation(void)
{
    struct rlimit old_limit;
    struct rlimit limit;
    struct group group;
    struct group *result;
    char buffer[64];
    int descriptor;

    setup();
    descriptor = open("/etc/group", O_WRONLY | O_TRUNC);
    CHECK(descriptor >= 0 && ftruncate(descriptor, 256 * 1024 * 1024) == 0 && !close(descriptor));
    CHECK(!getrlimit(RLIMIT_AS, &old_limit));
    limit = old_limit;
    limit.rlim_cur = 64 * 1024 * 1024;
    CHECK(!setrlimit(RLIMIT_AS, &limit));
    memset(buffer, 0x5a, sizeof(buffer));
    errno = 0;
    CHECK(getgrnam_r("absent", &group, buffer, sizeof(buffer), &result) == ENOMEM && !result);
    CHECK(errno == ENOMEM);
    for (size_t index = 0; index < sizeof(buffer); index++) {
        CHECK(buffer[index] == 0x5a);
    }
    for (int checked = 3; checked < 64; checked++) {
        CHECK(fcntl(checked, F_GETFD) == -1 && errno == EBADF);
    }
    CHECK(!setrlimit(RLIMIT_AS, &old_limit));
    setup();
    {
        char recovered[4096];
        CHECK(!getgrnam_r("team", &group, recovered, sizeof(recovered), &result) && result);
    }
}

int main(int argc, char **argv)
{
    CHECK(argc == 3);
    if (!strcmp(argv[1], "lookup")) {
        lookup();
    } else if (!strcmp(argv[1], "ranges")) {
        ranges();
    } else if (!strcmp(argv[1], "enumeration")) {
        enumeration();
    } else if (!strcmp(argv[1], "stream")) {
        setup();
        stream();
    } else if (!strcmp(argv[1], "output")) {
        setup();
        output();
    } else if (!strcmp(argv[1], "memberships")) {
        memberships();
    } else if (!strncmp(argv[1], "memberships-", 12)) {
        memberships_without_local_group(argv[1]);
    } else if (!strcmp(argv[1], "initgroups")) {
        initgroups_isolated();
    } else if (!strcmp(argv[1], "local-only")) {
        local_only(!strcmp(argv[2], "oracle"));
    } else if (!strcmp(argv[1], "threads")) {
        threads();
    } else if (!strcmp(argv[1], "fork")) {
        fork_cursor();
    } else if (!strcmp(argv[1], "cancellation")) {
        cancellation();
    } else if (!strcmp(argv[1], "allocation")) {
        allocation();
    } else {
        errors(argv[1]);
    }
    puts("owned group scenario passed");
    return 0;
}
