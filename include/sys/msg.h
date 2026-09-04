#ifndef _SYS_MSG_H
#define _SYS_MSG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <sys/ipc.h>
#if defined(__x86_64__)
#define __NEED_pid_t
#define __NEED_key_t
#define __NEED_time_t
#define __NEED_size_t
#define __NEED_ssize_t

#include <bits/alltypes.h>
#else
#include <sys/types.h>
#endif

typedef unsigned long msgqnum_t;
typedef unsigned long msglen_t;

#if defined(__x86_64__)
#include <bits/msg.h>
#else
struct msqid_ds {
	struct ipc_perm msg_perm;
	time_t msg_stime;
	time_t msg_rtime;
	time_t msg_ctime;
	unsigned long msg_cbytes;
	msgqnum_t msg_qnum;
	msglen_t msg_qbytes;
	pid_t msg_lspid;
	pid_t msg_lrpid;
	unsigned long __unused[2];
};
#endif

#define __msg_cbytes msg_cbytes

#define MSG_NOERROR 010000
#define MSG_EXCEPT  020000
#define MSG_STAT (11 | (IPC_STAT & 0x100))
#define MSG_INFO 12
#define MSG_STAT_ANY (13 | (IPC_STAT & 0x100))

struct msginfo {
	int msgpool, msgmap, msgmax, msgmnb, msgmni, msgssz, msgtql;
	unsigned short msgseg;
};
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
struct msgbuf {
	long mtype;
	char mtext[1];
};
#endif

int msgctl(int, int, struct msqid_ds *);
int msgget(key_t, int);
ssize_t msgrcv(int, void *, size_t, long, int);
int msgsnd(int, const void *, size_t, int);

#ifdef __cplusplus
}
#endif

#endif
