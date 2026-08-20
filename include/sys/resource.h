#ifndef _SYS_RESOURCE_H
#define _SYS_RESOURCE_H

#include <features.h>

/* Request only the types that this header's public declarations use.  A
 * blanket sys/types.h include leaks unrelated typedefs into the namespace
 * when <sys/resource.h> is included on its own. */
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define __NEED_id_t
#endif
#ifdef _GNU_SOURCE
#define __NEED_pid_t
#endif
#include <bits/alltypes.h>

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long rlim_t;

struct rlimit {
    rlim_t rlim_cur;
    rlim_t rlim_max;
};

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define RLIMIT_CPU      0
#endif
#define RLIMIT_FSIZE    1
#define RLIMIT_DATA     2
#define RLIMIT_STACK    3
#define RLIMIT_CORE     4
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define RLIMIT_RSS      5
#define RLIMIT_NPROC    6
#endif
#define RLIMIT_NOFILE   7
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define RLIMIT_MEMLOCK  8
#endif
#define RLIMIT_AS       9
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define RLIMIT_LOCKS    10
#define RLIMIT_SIGPENDING 11
#define RLIMIT_MSGQUEUE 12
#define RLIMIT_NICE     13
#define RLIMIT_RTPRIO   14
#define RLIMIT_RTTIME   15
#endif
#define RLIM_INFINITY   (~0UL)
#define RLIM_SAVED_MAX RLIM_INFINITY
#define RLIM_SAVED_CUR RLIM_INFINITY

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define PRIO_PROCESS 0
#define PRIO_PGRP 1
#define PRIO_USER 2
#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN -1
#endif

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
struct rusage {
    struct timeval ru_utime;
    struct timeval ru_stime;
    long ru_maxrss;
    long ru_ixrss;
    long ru_idrss;
    long ru_isrss;
    long ru_minflt;
    long ru_majflt;
    long ru_nswap;
    long ru_inblock;
    long ru_oublock;
    long ru_msgsnd;
    long ru_msgrcv;
    long ru_nsignals;
    long ru_nvcsw;
    long ru_nivcsw;
};
#endif

#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int getpriority(int, id_t);
int setpriority(int, id_t, int);
#endif
int getrlimit(int, struct rlimit *);
int setrlimit(int, const struct rlimit *);
#if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int getrusage(int, struct rusage *);
#endif

#ifdef _GNU_SOURCE
int prlimit(pid_t, int, const struct rlimit *, struct rlimit *);
#endif

#ifdef __cplusplus
}
#endif

#endif
