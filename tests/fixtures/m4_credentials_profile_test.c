#define _GNU_SOURCE 1

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <unistd.h>

static int same_uid_state(uid_t ruid, uid_t euid, uid_t suid)
{
    uid_t current_ruid, current_euid, current_suid;

    if (getresuid(&current_ruid, &current_euid, &current_suid) != 0)
        return 0;
    return current_ruid == ruid && current_euid == euid && current_suid == suid;
}

static int same_gid_state(gid_t rgid, gid_t egid, gid_t sgid)
{
    gid_t current_rgid, current_egid, current_sgid;

    if (getresgid(&current_rgid, &current_egid, &current_sgid) != 0)
        return 0;
    return current_rgid == rgid && current_egid == egid && current_sgid == sgid;
}

static int check_uid_setters(void)
{
    uid_t ruid, euid, suid;

    if (getresuid(&ruid, &euid, &suid) != 0)
        return 1;

    errno = 0;
    if (setreuid((uid_t)-1, euid) != -1 || errno != EOPNOTSUPP ||
        !same_uid_state(ruid, euid, suid))
        return 2;

    errno = 0;
    if (seteuid(euid) != -1 || errno != EOPNOTSUPP ||
        !same_uid_state(ruid, euid, suid))
        return 3;
    return 0;
}

static int check_gid_setters(void)
{
    gid_t rgid, egid, sgid;

    if (getresgid(&rgid, &egid, &sgid) != 0)
        return 1;

    errno = 0;
    if (setregid((gid_t)-1, egid) != -1 || errno != EOPNOTSUPP ||
        !same_gid_state(rgid, egid, sgid))
        return 2;

    errno = 0;
    if (setegid(egid) != -1 || errno != EOPNOTSUPP ||
        !same_gid_state(rgid, egid, sgid))
        return 3;
    return 0;
}

int main(void)
{
    if (check_uid_setters() != 0 || check_gid_setters() != 0)
        return 1;
    puts("m4 credentials profile ok");
    return 0;
}
