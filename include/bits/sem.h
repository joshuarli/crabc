
struct semid_ds {
	struct ipc_perm sem_perm;
	time_t sem_otime;
#if defined(__x86_64__)
	long __unused1;
#endif
	time_t sem_ctime;
#if defined(__x86_64__)
	long __unused2;
#endif
	unsigned short sem_nsems;
	char __sem_nsems_pad[sizeof(long)-sizeof(short)];
	long __unused3;
	long __unused4;
};
