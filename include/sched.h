#ifndef _SCHED_H
#define _SCHED_H

#include <sys/types.h>
#include <time.h>

struct sched_param { int sched_priority; };

#define SCHED_OTHER 0
#define SCHED_FIFO 1
#define SCHED_RR 2

int sched_get_priority_max(int);
int sched_get_priority_min(int);
int sched_getparam(pid_t, struct sched_param *);
int sched_getscheduler(pid_t);
int sched_setparam(pid_t, const struct sched_param *);
int sched_setscheduler(pid_t, int, const struct sched_param *);
int sched_rr_get_interval(pid_t, struct timespec *);
int sched_yield(void);

#endif
