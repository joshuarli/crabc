#if defined(__x86_64__)
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
#elif defined(__aarch64__)
/* musl 1.2.6 generic/bits/sem.h, MIT licensed. */
struct semid_ds {
	struct ipc_perm sem_perm;
	time_t sem_otime;
	time_t sem_ctime;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned short sem_nsems;
	char __sem_nsems_pad[sizeof(long)-sizeof(short)];
#else
	char __sem_nsems_pad[sizeof(long)-sizeof(short)];
	unsigned short sem_nsems;
#endif
	long __unused3;
	long __unused4;
};

#endif
