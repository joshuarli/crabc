#ifndef _SYS_TYPES_H
#define _SYS_TYPES_H

#if defined(__x86_64__)
/*
 * The staged x86 surface follows musl's request-based type ownership: this
 * umbrella header asks `bits/alltypes.h` for its vocabulary instead of
 * becoming a second definition site.  Keep the legacy AArch64 body below;
 * its public pthread and stat-facing type contract is independently frozen.
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#define __NEED_ino_t
#define __NEED_dev_t
#define __NEED_uid_t
#define __NEED_gid_t
#define __NEED_mode_t
#define __NEED_nlink_t
#define __NEED_off_t
#define __NEED_pid_t
#define __NEED_size_t
#define __NEED_ssize_t
#define __NEED_time_t
#define __NEED_timer_t
#define __NEED_clockid_t

#define __NEED_blkcnt_t
#define __NEED_fsblkcnt_t
#define __NEED_fsfilcnt_t

#define __NEED_id_t
#define __NEED_key_t
#define __NEED_clock_t
#define __NEED_suseconds_t
#define __NEED_blksize_t

#define __NEED_pthread_t
#define __NEED_pthread_attr_t
#define __NEED_pthread_mutexattr_t
#define __NEED_pthread_condattr_t
#define __NEED_pthread_rwlockattr_t
#define __NEED_pthread_barrierattr_t
#define __NEED_pthread_mutex_t
#define __NEED_pthread_cond_t
#define __NEED_pthread_rwlock_t
#define __NEED_pthread_barrier_t
#define __NEED_pthread_spinlock_t
#define __NEED_pthread_key_t
#define __NEED_pthread_once_t
#define __NEED_useconds_t

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define __NEED_int8_t
#define __NEED_int16_t
#define __NEED_int32_t
#define __NEED_int64_t
#define __NEED_u_int64_t
#define __NEED_register_t
#endif

#include <bits/alltypes.h>

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned u_int32_t;
typedef char *caddr_t;
typedef unsigned char u_char;
typedef unsigned short u_short, ushort;
typedef unsigned u_int, uint;
typedef unsigned long u_long, ulong;
typedef long long quad_t;
typedef unsigned long long u_quad_t;
#include <endian.h>
#include <sys/select.h>
#endif

#if defined(_LARGEFILE64_SOURCE)
#define blkcnt64_t blkcnt_t
#define fsblkcnt64_t fsblkcnt_t
#define fsfilcnt64_t fsfilcnt_t
#define ino64_t ino_t
#define off64_t off_t
#endif

#ifdef __cplusplus
}
#endif

#else

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
#ifndef __DEFINED_fsblkcnt_t
#define __DEFINED_fsblkcnt_t
typedef unsigned long fsblkcnt_t;
#endif
#ifndef __DEFINED_fsfilcnt_t
#define __DEFINED_fsfilcnt_t
typedef unsigned long fsfilcnt_t;
#endif
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

#endif
