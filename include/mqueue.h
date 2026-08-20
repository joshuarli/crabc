#ifndef _MQUEUE_H
#define _MQUEUE_H

#include <sys/types.h>
#include <time.h>
#include <signal.h>

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
int mq_setattr(mqd_t, const struct mq_attr *restrict, struct mq_attr *restrict);
int mq_unlink(const char *);
ssize_t mq_timedreceive(mqd_t, char *restrict, size_t, unsigned *restrict, const struct timespec *restrict);
int mq_timedsend(mqd_t, const char *, size_t, unsigned, const struct timespec *);

#endif
