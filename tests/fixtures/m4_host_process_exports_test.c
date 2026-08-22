#define _GNU_SOURCE 1

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* The local public sys/time.h is intentionally small; keep this fixture's
 * declaration explicit while the exported ABI remains the Linux layout. */
struct itimerval {
    struct timeval it_interval;
    struct timeval it_value;
};

extern int getdomainname(char *, size_t);
extern int setdomainname(const char *, size_t);
extern int sethostname(const char *, size_t);
extern int getresuid(uid_t *, uid_t *, uid_t *);
extern int setresuid(uid_t, uid_t, uid_t);
extern int getresgid(gid_t *, gid_t *, gid_t *);
extern int setresgid(gid_t, gid_t, gid_t);
extern int getitimer(int, struct itimerval *);
extern int setitimer(int, const struct itimerval *, struct itimerval *);
extern unsigned ualarm(unsigned, unsigned);

#define ITIMER_REAL 0

static int check_privileged_setters(const struct utsname *before)
{
    char replacement[] = "crabc-m4-host";
    int result;

    errno = 0;
    result = sethostname(replacement, sizeof replacement - 1);
    if (result == 0) {
        /* A privileged test environment is valid too; never leave the
         * process namespace changed if Linux allowed the mutation. */
        if (sethostname(before->nodename, strlen(before->nodename)) != 0)
            return 1;
    } else if (errno != EPERM && errno != ENOSYS) {
        return 2;
    }

    errno = 0;
    result = setdomainname(replacement, sizeof replacement - 1);
    if (result == 0) {
        if (setdomainname(before->domainname, strlen(before->domainname)) != 0)
            return 3;
    } else if (errno != EPERM && errno != ENOSYS) {
        return 4;
    }
    return 0;
}

int main(void)
{
    struct utsname uts;
    struct rusage usage;
    struct itimerval timer;
    struct itimerval old;
    struct tms cpu;
    char domain[65];
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    clock_t elapsed;

    memset(&uts, 0, sizeof uts);
    if (uname(&uts) != 0 || strcmp(uts.sysname, "Linux") != 0 ||
        !uts.nodename[0] || !uts.machine[0])
        return 1;
    if (getdomainname(domain, sizeof domain) != 0 ||
        strcmp(domain, uts.domainname) != 0)
        return 2;
    errno = 0;
    if (getdomainname(domain, 0) != -1 || errno != EINVAL)
        return 3;
    if (check_privileged_setters(&uts) != 0)
        return 4;
    if (gethostid() != 0)
        return 5;
    if (issetugid() != 0)
        return 13;

    if (getresuid(&ruid, &euid, &suid) != 0 ||
        setresuid((uid_t)-1, (uid_t)-1, (uid_t)-1) != 0)
        return 6;
    if (getresgid(&rgid, &egid, &sgid) != 0 ||
        setresgid((gid_t)-1, (gid_t)-1, (gid_t)-1) != 0)
        return 7;
    errno = 0;
    if (setgroups((size_t)-1, NULL) != -1 || errno != EINVAL)
        return 14;

    memset(&usage, 0, sizeof usage);
    if (getrusage(RUSAGE_SELF, &usage) != 0 ||
        usage.ru_utime.tv_sec < 0 || usage.ru_utime.tv_usec < 0 ||
        usage.ru_stime.tv_sec < 0 || usage.ru_stime.tv_usec < 0)
        return 8;
    errno = 0;
    if (getrusage(99, &usage) != -1 || errno != EINVAL)
        return 9;

    memset(&timer, 0, sizeof timer);
    memset(&old, 0, sizeof old);
    if (setitimer(ITIMER_REAL, &timer, &old) != 0 ||
        getitimer(ITIMER_REAL, &old) != 0 ||
        old.it_value.tv_sec != 0 || old.it_value.tv_usec != 0 ||
        old.it_interval.tv_sec != 0 || old.it_interval.tv_usec != 0)
        return 10;
    /* musl's alarm contract ceilings a positive fractional remainder. */
    if (ualarm(125000, 0) != 0 || alarm(0) != 1)
        return 15;
    if (ualarm(0, 0) != 0)
        return 11;

    memset(&cpu, 0, sizeof cpu);
    elapsed = times(&cpu);
    if (elapsed == (clock_t)-1 || cpu.tms_utime < 0 || cpu.tms_stime < 0 ||
        cpu.tms_cutime < 0 || cpu.tms_cstime < 0)
        return 12;

    puts("m4 host process exports ok");
    return 0;
}
