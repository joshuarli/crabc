#ifndef _SYS_TYPES_H
#define _SYS_TYPES_H

/*
 * This is the common public type vocabulary for the staged Linux ABIs.
 * Keeping these definitions here avoids subtly incompatible private copies in
 * the individual POSIX headers: consumers routinely include only sys/types.h.
 */
#include <features.h>

#ifndef __DEFINED_size_t
#define __DEFINED_size_t
typedef __SIZE_TYPE__ size_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long dev_t;
typedef unsigned long ino_t;
typedef unsigned int mode_t;
#if defined(__aarch64__)
/* The modern stat ABI uses the kernel-width link-count and block-size
 * fields on these targets.  They are not pointer-width types in musl's
 * public vocabulary, even though dev_t/ino_t remain unsigned long. */
typedef unsigned int nlink_t;
#else
typedef unsigned long nlink_t;
#endif
typedef long off_t;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
#if defined(__aarch64__)
typedef int blksize_t;
#else
typedef long blksize_t;
#endif
typedef long blkcnt_t;
typedef unsigned long fsblkcnt_t;
typedef unsigned long fsfilcnt_t;
typedef unsigned int id_t;
typedef int key_t;
typedef long time_t;
typedef long clock_t;
typedef int clockid_t;
typedef void *timer_t;
typedef long suseconds_t;
typedef unsigned int useconds_t;
typedef long ssize_t;

#ifndef _PTHREAD_TYPES_DEFINED
#define _PTHREAD_TYPES_DEFINED
#if defined(__x86_64__) && !defined(__cplusplus)
typedef struct __pthread *pthread_t;
#else
typedef unsigned long pthread_t;
#endif
typedef struct { unsigned __attr; } pthread_mutexattr_t;
typedef struct { unsigned __attr; } pthread_condattr_t;
typedef struct { unsigned __attr[2]; } pthread_rwlockattr_t;
typedef struct { unsigned __attr; } pthread_barrierattr_t;
typedef struct {
    union { int __i[10]; volatile int __vi[10]; volatile void *volatile __p[5]; } __u;
} pthread_mutex_t;
typedef struct {
    union { int __i[12]; volatile int __vi[12]; void *__p[6]; } __u;
} pthread_cond_t;
typedef struct {
    union { int __i[14]; volatile int __vi[14]; void *__p[7]; } __u;
} pthread_rwlock_t;
typedef struct {
    union { int __i[8]; volatile int __vi[8]; void *__p[4]; } __u;
} pthread_barrier_t;
typedef int pthread_spinlock_t;
typedef int pthread_once_t;
typedef unsigned pthread_key_t;
typedef struct {
    union { int __i[14]; volatile int __vi[14]; unsigned long __s[7]; } __u;
} pthread_attr_t;
#endif

#ifdef __cplusplus
}
#endif

#endif
