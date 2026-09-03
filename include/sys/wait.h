#ifndef _SYS_WAIT_H
#define _SYS_WAIT_H
#if defined(__x86_64__)
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>

#define __NEED_pid_t
#define __NEED_id_t
#include <bits/alltypes.h>

typedef enum {
	P_ALL = 0,
	P_PID = 1,
	P_PGID = 2,
	P_PIDFD = 3
} idtype_t;

pid_t wait (int *);
pid_t waitpid (pid_t, int *, int );

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
#include <signal.h>
int waitid (idtype_t, id_t, siginfo_t *, int);
#endif

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#include <sys/resource.h>
pid_t wait3 (int *, int, struct rusage *);
pid_t wait4 (pid_t, int *, int, struct rusage *);
#endif

#define WNOHANG    1
#define WUNTRACED  2

#define WSTOPPED   2
#define WEXITED    4
#define WCONTINUED 8
#define WNOWAIT    0x1000000

#define __WNOTHREAD 0x20000000
#define __WALL      0x40000000
#define __WCLONE    0x80000000

#define WEXITSTATUS(s) (((s) & 0xff00) >> 8)
#define WTERMSIG(s) ((s) & 0x7f)
#define WSTOPSIG(s) WEXITSTATUS(s)
#define WCOREDUMP(s) ((s) & 0x80)
#define WIFEXITED(s) (!WTERMSIG(s))
#define WIFSTOPPED(s) ((short)((((s)&0xffff)*0x10001U)>>8) > 0x7f00)
#define WIFSIGNALED(s) (((s)&0xffff)-1U < 0xffu)
#define WIFCONTINUED(s) ((s) == 0xffff)

#if _REDIR_TIME64
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
__REDIR(wait3, __wait3_time64);
__REDIR(wait4, __wait4_time64);
#endif
#endif

#ifdef __cplusplus
}
#endif
#else

#include <sys/types.h>
#include <signal.h>

typedef enum { P_ALL = 0, P_PID = 1, P_PGID = 2 } idtype_t;

/* These historical BSD/GNU wait extensions carry `struct rusage` output.
 * Keep both the dependent record and declarations out of strict/POSIX source
 * profiles, matching pinned musl 1.2.6 rather than widening sys/wait.h by
 * accident. */
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#include <sys/resource.h>
#endif

#define WNOHANG 1
#define WUNTRACED 2
#define WSTOPPED WUNTRACED
#define WEXITED 4
#define WCONTINUED 8
#define WNOWAIT 0x01000000
#define WEXITSTATUS(s) (((s) & 0xff00) >> 8)
#ifndef WIFEXITED
#define WIFEXITED(s) (((s) & 0x7f) == 0)
#endif
#ifndef WIFSIGNALED
#define WIFSIGNALED(s) (((s)&0xffff)-1U < 0xffu)
#endif
#define WIFSTOPPED(s) ((short)((((s)&0xffff)*0x10001U)>>8) > 0x7f00)
#define WSTOPSIG(s) WEXITSTATUS(s)
#define WTERMSIG(s) ((s) & 0x7f)
#define WCOREDUMP(s) ((s) & 0x80)
#define WIFCONTINUED(s) ((s) == 0xffff)

#ifdef __cplusplus
extern "C" {
#endif

pid_t wait(int *);
pid_t waitpid(pid_t, int *, int);
int waitid(idtype_t, id_t, siginfo_t *, int);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
pid_t wait3(int *, int, struct rusage *);
pid_t wait4(pid_t, int *, int, struct rusage *);
#endif

#ifdef __cplusplus
}
#endif

#endif
#endif
