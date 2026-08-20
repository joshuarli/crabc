#ifndef _SYS_WAIT_H
#define _SYS_WAIT_H

#include <sys/types.h>
#include <signal.h>

typedef enum { P_ALL = 0, P_PID = 1, P_PGID = 2 } idtype_t;

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
#define WIFSIGNALED(s) (((s) & 0x7f) != 0 && (((s) & 0x7f) != 0x7f))
#endif
#define WIFSTOPPED(s) (((s) & 0xff) == 0x7f)
#define WSTOPSIG(s) WEXITSTATUS(s)
#define WTERMSIG(s) ((s) & 0x7f)
#define WCOREDUMP(s) ((s) & 0x80)
#define WIFCONTINUED(s) ((s) == 0xffff)

pid_t wait(int *);
pid_t waitpid(pid_t, int *, int);
int waitid(idtype_t, id_t, siginfo_t *, int);

#endif
