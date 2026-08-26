/* Pinned-musl Linux/x86-64 process-identity behavior reference. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    pid_t pid = getpid();
    pid_t parent = getppid();
    uid_t uid = getuid();
    uid_t euid = geteuid();
    gid_t gid = getgid();
    gid_t egid = getegid();
    uid_t ruid;
    uid_t reuid;
    uid_t suid;
    gid_t rgid;
    gid_t regid;
    gid_t sgid;

    if (pid <= 0 || parent < 0 || uid == (uid_t)-1 ||
        euid == (uid_t)-1 || gid == (gid_t)-1 || egid == (gid_t)-1) {
        return 1;
    }
    if (getresuid(&ruid, &reuid, &suid) != 0 ||
        getresgid(&rgid, &regid, &sgid) != 0) {
        return 2;
    }
    if (ruid != uid || reuid != euid || rgid != gid || regid != egid ||
        suid == (uid_t)-1 || sgid == (gid_t)-1) {
        return 3;
    }
    if (getpid() != pid || getppid() != parent || getuid() != uid ||
        geteuid() != euid || getgid() != gid || getegid() != egid) {
        return 4;
    }

    puts("pid=positive parent=nonnegative ids=stable");
    return 0;
}
