/*
 * Link and query witness for the residual portion of the frozen
 * system.kernel-admin roster.  It is intentionally limited to source-safe
 * query paths: sethostname and setdomainname are referenced behind an unused
 * command-line branch so this first provider regression never mutates a UTS
 * namespace.  The behavioral workload supplies their contained paths later.
 */
#define _GNU_SOURCE 1

#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/membarrier.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ulimit.h>
#include <unistd.h>

static volatile long observed;

int main(int argc, char **argv)
{
    cpu_set_t set;
    struct sched_param parameter;
    char configuration[32];
    char hostname[] = "crabc-kernel-residual";
    char domainname[] = "crabc-residual";

    (void)argv;
    memset(&set, 0, sizeof set);
    memset(&parameter, 0xa5, sizeof parameter);

    observed += __sched_cpucount(sizeof set, &set);
    observed += (long)confstr(_CS_PATH, configuration, sizeof configuration);
    observed += fpathconf(-1, _PC_LINK_MAX);
    observed += getdtablesize();
    observed += gethostid();
    observed += membarrier(MEMBARRIER_CMD_QUERY, 0);
    observed += pathconf("/", _PC_PATH_MAX);
    observed += personality(~0UL);
    observed += prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL);
    observed += sched_getparam(0, &parameter);
    observed += sched_getscheduler(0);
    observed += sched_setparam(0, &parameter);
    observed += sched_setscheduler(0, SCHED_OTHER, &parameter);
    observed += syscall(SYS_getpid, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL);
    observed += sysconf(_SC_CLK_TCK);
    observed += ulimit(UL_GETFSIZE);

    if (argc == 2) {
        observed += sethostname(hostname, sizeof hostname - 1);
        observed += setdomainname(domainname, sizeof domainname - 1);
    }

    if (observed == LONG_MIN) return 1;
    puts("owned-kernel-residual-link-ok");
    return 0;
}
