#include <stddef.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>

/* Ensure the opaque initializers remain source-compatible with musl too. */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

int main(void) {
    (void)mutex;
    (void)cond;
    (void)rwlock;

    printf("fpos %zu %zu\n", sizeof(fpos_t), _Alignof(fpos_t));

    printf("stat %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu\n",
           sizeof(struct stat), _Alignof(struct stat),
           offsetof(struct stat, st_dev), offsetof(struct stat, st_ino),
           offsetof(struct stat, st_mode), offsetof(struct stat, st_nlink),
           offsetof(struct stat, st_uid), offsetof(struct stat, st_gid),
           offsetof(struct stat, st_rdev), offsetof(struct stat, st_size),
           offsetof(struct stat, st_blksize), offsetof(struct stat, st_blocks),
           offsetof(struct stat, st_atim), offsetof(struct stat, st_mtim),
           offsetof(struct stat, st_ctim));

    printf("stack %zu %zu %zu %zu %zu %d %d\n",
           sizeof(stack_t), _Alignof(stack_t), offsetof(stack_t, ss_sp),
           offsetof(stack_t, ss_flags), offsetof(stack_t, ss_size),
           MINSIGSTKSZ, SIGSTKSZ);
    printf("sigset %zu %zu\n", sizeof(sigset_t), _Alignof(sigset_t));

    printf("sigaction %zu %zu %zu %zu %zu %zu\n",
           sizeof(struct sigaction), _Alignof(struct sigaction),
           sizeof(((struct sigaction *)0)->sa_flags),
           offsetof(struct sigaction, sa_mask),
           offsetof(struct sigaction, sa_flags),
           offsetof(struct sigaction, sa_restorer));

    printf("mcontext %zu %zu %zu %zu %zu %zu %zu %zu %zu\n",
           sizeof(mcontext_t), _Alignof(mcontext_t),
           sizeof(gregset_t), sizeof(fpregset_t),
           offsetof(mcontext_t, fault_address),
           offsetof(mcontext_t, regs), offsetof(mcontext_t, sp),
           offsetof(mcontext_t, pc), offsetof(mcontext_t, pstate));

    printf("pthread %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu\n",
           sizeof(pthread_t), _Alignof(pthread_t),
           sizeof(pthread_attr_t), _Alignof(pthread_attr_t),
           sizeof(pthread_mutex_t), _Alignof(pthread_mutex_t),
           sizeof(pthread_cond_t), _Alignof(pthread_cond_t),
           sizeof(pthread_rwlock_t), _Alignof(pthread_rwlock_t),
           sizeof(pthread_barrier_t), _Alignof(pthread_barrier_t),
           sizeof(pthread_mutexattr_t), sizeof(pthread_rwlockattr_t));
    return 0;
}
