#ifndef _SYS_WAIT_H
#define _SYS_WAIT_H

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
