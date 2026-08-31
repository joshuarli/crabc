#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H

#include <features.h>

#ifdef __cplusplus
extern "C" {
#endif

#define __NEED_time_t
#define __NEED_struct_timespec
#include <bits/alltypes.h>

#include <fcntl.h>

/* Match musl's public 32-byte x86 semaphore record.  The first three words
 * are the selected unnamed-semaphore value, waiter count, and futex-sharing
 * flag; consumers must not decode them. */
typedef struct { volatile int __val[4 * sizeof(long) / sizeof(int)]; } sem_t;

#define SEM_FAILED ((sem_t *)0)

int sem_init(sem_t *, int, unsigned);
int sem_destroy(sem_t *);
int sem_wait(sem_t *);
int sem_trywait(sem_t *);
int sem_timedwait(sem_t *__restrict, const struct timespec *__restrict);
int sem_post(sem_t *);
int sem_getvalue(sem_t *, int *);

sem_t *sem_open(const char *, int, ...);
int sem_close(sem_t *);
int sem_unlink(const char *);

#ifdef __cplusplus
}
#endif

#endif
