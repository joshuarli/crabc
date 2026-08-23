#define _GNU_SOURCE 1

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

extern void *malloc(size_t);
extern void free(void *);

static int group_ok(const struct group *group)
{
    return group && group->gr_name && group->gr_passwd && group->gr_mem;
}

static int members_equal(const struct group *group, const char *first,
    const char *second)
{
    return group_ok(group) && group->gr_mem[0] && group->gr_mem[1] &&
        strcmp(group->gr_mem[0], first) == 0 &&
        strcmp(group->gr_mem[1], second) == 0 && !group->gr_mem[2];
}

static int members_valid(const struct group *group)
{
    unsigned int index;

    if (!group_ok(group))
        return 0;
    for (index = 0; index < 1024; index++) {
        if (!group->gr_mem[index])
            return 1;
        if (!group->gr_mem[index][0])
            return 0;
    }
    return 0;
}

/* initgroups changes supplementary credentials when authorized.  Exercise its
 * real setgroups path in a child so this fixture never changes the harness
 * process that owns subsequent loader tests. */
static int initgroups_in_child(const char *user, gid_t group)
{
    pid_t child = fork();
    int status;

    if (child < 0)
        return 0;
    if (child == 0) {
        errno = 0;
        if (initgroups(user, group) == 0 || errno == EPERM)
            _exit(0);
        _exit(1);
    }
    if (waitpid(child, &status, 0) != child)
        return 0;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(void)
{
    gid_t gid = getgid();
    uid_t uid = getuid();
    struct group *direct;
    struct group output;
    struct group *result = (struct group *)1;
    char name[256];
    char buffer[4096];
    char tiny[1];
    int rc;
    unsigned int count = 0;
    char first_name[256];
    gid_t first_gid;
    FILE *stream;
    struct group controlled;
    char *controlled_members[] = {
        (char *)"crabc-member-a",
        (char *)"crabc-member-b",
        NULL,
    };
    struct passwd *user_record;
    gid_t *groups;
    int group_count;
    int before_groups;
    int after_groups;

    direct = getgrgid(gid);
    if (!group_ok(direct) || direct->gr_gid != gid)
        return 1;
    strncpy(name, direct->gr_name, sizeof(name) - 1);
    name[sizeof(name) - 1] = 0;
    direct = getgrnam(name);
    if (!group_ok(direct) || direct->gr_gid != gid ||
        strcmp(direct->gr_name, name) != 0)
        return 2;

    result = (struct group *)1;
    rc = getgrgid_r(gid, &output, tiny, sizeof(tiny), &result);
    if (rc != ERANGE || result != NULL)
        return 3;
    result = (struct group *)1;
    rc = getgrgid_r(gid, &output, NULL, 0, &result);
    if (rc != ERANGE || result != NULL)
        return 4;
    result = (struct group *)1;
    rc = getgrgid_r(gid, &output, buffer, sizeof(buffer), &result);
    if (rc != 0 || result != &output || !members_valid(result) ||
        result->gr_gid != gid || strcmp(result->gr_name, name) != 0)
        return 5;
    result = (struct group *)1;
    rc = getgrnam_r("crabc-group-that-does-not-exist", &output,
        buffer, sizeof(buffer), &result);
    if (rc != 0 || result != NULL)
        return 6;

    setgrent();
    direct = getgrent();
    if (!group_ok(direct))
        return 7;
    strncpy(first_name, direct->gr_name, sizeof(first_name) - 1);
    first_name[sizeof(first_name) - 1] = 0;
    first_gid = direct->gr_gid;
    setgrent();
    direct = getgrent();
    if (!group_ok(direct) || direct->gr_gid != first_gid ||
        strcmp(direct->gr_name, first_name) != 0)
        return 8;
    do {
        direct = getgrent();
        if (direct && !group_ok(direct))
            return 9;
        if (direct && ++count > 1024)
            return 10;
    } while (direct);
    endgrent();
    direct = getgrent();
    if (!group_ok(direct))
        return 11;
    endgrent();

    controlled.gr_name = (char *)"crabc-roundtrip";
    controlled.gr_passwd = (char *)"x";
    controlled.gr_gid = 5432;
    controlled.gr_mem = controlled_members;
    stream = tmpfile();
    if (!stream || putgrent(&controlled, stream) != 0)
        return 12;
    rewind(stream);
    direct = fgetgrent(stream);
    if (!group_ok(direct) || direct->gr_gid != controlled.gr_gid ||
        strcmp(direct->gr_name, controlled.gr_name) != 0 ||
        strcmp(direct->gr_passwd, controlled.gr_passwd) != 0 ||
        !members_equal(direct, controlled_members[0], controlled_members[1]))
        return 13;
    fclose(stream);

    user_record = getpwuid(uid);
    if (!user_record || !user_record->pw_name)
        return 14;
    group_count = 0;
    rc = getgrouplist(user_record->pw_name, gid, NULL, &group_count);
    if (rc != -1 || group_count < 1)
        return 15;
    groups = malloc((size_t)group_count * sizeof(*groups));
    if (!groups)
        return 16;
    before_groups = getgroups(0, NULL);
    rc = getgrouplist(user_record->pw_name, gid, groups, &group_count);
    after_groups = getgroups(0, NULL);
    if (rc != 0 || group_count < 1 || groups[0] != gid ||
        before_groups < 0 || after_groups != before_groups) {
        free(groups);
        return 17;
    }
    free(groups);

    errno = 0;
    if (initgroups(NULL, gid) != -1 || errno != EINVAL)
        return 18;
    if (!initgroups_in_child(user_record->pw_name, gid))
        return 19;

    puts("c-abi group ok");
    return 0;
}
