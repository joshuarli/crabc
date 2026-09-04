#ifndef _BITS_SEM_H
#define _BITS_SEM_H

/* Linux/x86-64 System V semaphore record from pinned musl. */
#if !defined(__x86_64__) || !defined(__LP64__)
#error "crabc x86-64 bits/sem.h requires LP64 x86-64"
#endif

struct semid_ds {
	struct ipc_perm sem_perm;
	time_t sem_otime;
	long __unused1;
	time_t sem_ctime;
	long __unused2;
	unsigned short sem_nsems;
	char __sem_nsems_pad[sizeof(long)-sizeof(short)];
	long __unused3;
	long __unused4;
};

#endif
