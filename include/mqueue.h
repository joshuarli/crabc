#ifndef _MQUEUE_H
#define _MQUEUE_H

#if defined(__x86_64__)
#include <features.h>

#define __NEED_size_t
#define __NEED_ssize_t
#define __NEED_pthread_attr_t
#define __NEED_time_t
#define __NEED_struct_timespec
#include <bits/alltypes.h>
#else
#include <sys/types.h>
#endif

struct sigevent;
#ifndef __DEFINED_struct_timespec
#define __DEFINED_struct_timespec
struct timespec {
    long tv_sec;
    long tv_nsec;
};
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MQ_PRIO_MAX 32768

typedef int mqd_t;
struct mq_attr {
    long mq_flags;
    long mq_maxmsg;
    long mq_msgsize;
    long mq_curmsgs;
    long __reserved[4];
};

int mq_close(mqd_t);
int mq_getattr(mqd_t, struct mq_attr *);
int mq_notify(mqd_t, const struct sigevent *);
mqd_t mq_open(const char *, int, ...);
ssize_t mq_receive(mqd_t, char *, size_t, unsigned *);
int mq_send(mqd_t, const char *, size_t, unsigned);
int mq_setattr(mqd_t, const struct mq_attr *__restrict, struct mq_attr *__restrict);
int mq_unlink(const char *);
ssize_t mq_timedreceive(mqd_t, char *__restrict, size_t, unsigned *__restrict, const struct timespec *__restrict);
int mq_timedsend(mqd_t, const char *, size_t, unsigned, const struct timespec *);

#ifdef __cplusplus
}
#endif

#endif
