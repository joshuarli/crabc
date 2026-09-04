#ifndef _BITS_MSG_H
#define _BITS_MSG_H

/* Linux/x86-64 System V message queue record from pinned musl. */
#if !defined(__x86_64__) || !defined(__LP64__)
#error "crabc x86-64 bits/msg.h requires LP64 x86-64"
#endif

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
