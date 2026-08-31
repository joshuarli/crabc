#ifndef _SCHED_H
#define _SCHED_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <time.h>

/* This reserve is public ABI, even though the currently implemented
 * scheduling calls consume only sched_priority.  Keep the musl 1.2.6
 * LP64 layout so a struct sched_param crosses pthread and sched boundaries
 * with the same size and alignment as the C/POSIX oracle. */
struct sched_param {
    int sched_priority;
    int __reserved1;
#if defined(_REDIR_TIME64) && _REDIR_TIME64
    long __reserved2[4];
#else
    struct {
        time_t __reserved1;
        long __reserved2;
    } __reserved2[2];
#endif
    int __reserved3;
};

#define SCHED_OTHER 0
#define SCHED_FIFO 1
#define SCHED_RR 2
#define SCHED_BATCH 3
#define SCHED_IDLE 5
#define SCHED_DEADLINE 6
#define SCHED_RESET_ON_FORK 0x40000000

#ifdef _GNU_SOURCE
/* Linux's GNU pthread-affinity entries exchange this fixed 1024-bit mask.
 * Keep musl 1.2.6's tagged type, capacity, and unsigned-long storage so the
 * pointer declarations in pthread.h are constructible by C and C++ callers
 * without inventing a separate x86-only public representation. The CPU_*
 * construction/allocation helper macro family remains unselected. */
typedef struct cpu_set_t {
    unsigned long __bits[128 / sizeof(long)];
} cpu_set_t;

#define CSIGNAL             0x000000ff
#define CLONE_NEWTIME       0x00000080
#define CLONE_VM            0x00000100
#define CLONE_FS            0x00000200
#define CLONE_FILES         0x00000400
#define CLONE_SIGHAND       0x00000800
#define CLONE_PIDFD         0x00001000
#define CLONE_PTRACE        0x00002000
#define CLONE_VFORK         0x00004000
#define CLONE_PARENT        0x00008000
#define CLONE_THREAD        0x00010000
#define CLONE_NEWNS         0x00020000
#define CLONE_SYSVSEM       0x00040000
#define CLONE_SETTLS        0x00080000
#define CLONE_PARENT_SETTID 0x00100000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_DETACHED      0x00400000
#define CLONE_UNTRACED      0x00800000
#define CLONE_CHILD_SETTID  0x01000000
#define CLONE_NEWCGROUP     0x02000000
#define CLONE_NEWUTS        0x04000000
#define CLONE_NEWIPC        0x08000000
#define CLONE_NEWUSER       0x10000000
#define CLONE_NEWPID        0x20000000
#define CLONE_NEWNET        0x40000000
#define CLONE_IO            0x80000000

int clone(int (*)(void *), void *, int, void *, ...);
int sched_getcpu(void);
#endif

int sched_get_priority_max(int);
int sched_get_priority_min(int);
int sched_getparam(pid_t, struct sched_param *);
int sched_getscheduler(pid_t);
int sched_setparam(pid_t, const struct sched_param *);
int sched_setscheduler(pid_t, int, const struct sched_param *);
int sched_rr_get_interval(pid_t, struct timespec *);
int sched_yield(void);

#ifdef __cplusplus
}
#endif

#endif
