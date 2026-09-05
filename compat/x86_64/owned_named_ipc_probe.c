#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include "owned_cancellation_proc_witness.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"named-ipc:%d: %s errno=%d\n",__LINE__,#x,errno); _Exit(95); } } while (0)
static void child_ok(pid_t child) { int status; CHECK(waitpid(child,&status,0)==child); CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0); }
static void bad_name(const char *name,int error) {
    errno=0; CHECK(sem_open(name,0)==SEM_FAILED && errno==error);
    errno=0; CHECK(shm_open(name,O_RDONLY,0)==-1 && errno==error);
    errno=0; CHECK(sem_unlink(name)==-1 && errno==error);
    errno=0; CHECK(shm_unlink(name)==-1 && errno==error);
}
static void namespace_rules(void) {
    bad_name("",EINVAL); bad_name("/",EINVAL); bad_name(".",EINVAL);
    bad_name("///..",EINVAL); bad_name("a/b",EINVAL);
    char name[260]; memset(name,'n',256); name[256]=0; bad_name(name,ENAMETOOLONG);
    name[256]='/'; name[257]=0; bad_name(name,EINVAL);
    name[255]=0; int fd=shm_open(name,O_CREAT|O_EXCL|O_RDWR,0600); CHECK(fd>=0);
    CHECK(close(fd)==0 && shm_unlink(name)==0);
    bad_name("/missing",ENOENT);
    CHECK(symlink("target","/dev/shm/symlink")==0);
    errno=0; CHECK(sem_open("symlink",0)==SEM_FAILED && errno==ELOOP);
    errno=0; CHECK(shm_open("symlink",O_RDONLY,0)==-1 && errno==ELOOP);
    CHECK(shm_unlink("symlink")==0);
    errno=0; CHECK(sem_open("invalid-value",O_CREAT|O_EXCL,0600,~0U)==SEM_FAILED && errno==EINVAL);
    errno=0; CHECK(shm_open("invalid-value",O_RDONLY,0)==-1 && errno==ENOENT);
}
static void shared_namespace_and_lifetime(void) {
    mode_t previous=umask(0027);
    sem_t *first=sem_open("///named",O_CREAT|O_EXCL,0777,2U); CHECK(first!=SEM_FAILED);
    int fd=shm_open("named",O_RDONLY,0); CHECK(fd>=0);
    struct stat status; CHECK(fstat(fd,&status)==0 && status.st_size==sizeof(sem_t));
    CHECK((status.st_mode&0777)==0640);
    CHECK((fcntl(fd,F_GETFD)&FD_CLOEXEC)!=0 && (fcntl(fd,F_GETFL)&O_NONBLOCK)!=0);
    CHECK(close(fd)==0);
    sem_t *second=sem_open("named",O_CREAT|O_TRUNC,0000,~0U); CHECK(second==first);
    int value; CHECK(sem_getvalue(first,&value)==0 && value==2);
    errno=0; CHECK(sem_open("named",O_CREAT|O_EXCL,0600,~0U)==SEM_FAILED && errno==EEXIST);
    CHECK(link("/dev/shm/named","/dev/shm/alias")==0);
    sem_t *alias=sem_open("alias",0); CHECK(alias==first);
    CHECK(sem_close(second)==0 && sem_close(alias)==0);
    CHECK(shm_unlink("alias")==0 && shm_unlink("named")==0);
    sem_t *replacement=sem_open("named",O_CREAT|O_EXCL,0600,7U);
    CHECK(replacement!=SEM_FAILED && replacement!=first);
    CHECK(sem_wait(first)==0 && sem_getvalue(first,&value)==0 && value==1);
    CHECK(sem_getvalue(replacement,&value)==0 && value==7);
    CHECK(sem_close(first)==0);
    unsigned char residency; errno=0;
    CHECK(mincore(first,1,&residency)==-1 && errno==ENOMEM);
    CHECK(sem_unlink("named")==0 && sem_close(replacement)==0);
    fd=shm_open("memory",O_CREAT|O_EXCL|O_RDWR,0777); CHECK(fd>=0);
    CHECK(fstat(fd,&status)==0 && (status.st_mode&0777)==0750);
    umask(previous);
    CHECK(ftruncate(fd,4096)==0);
    sem_t *mapped=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0); CHECK(mapped!=MAP_FAILED);
    CHECK(sem_init(mapped,1,3)==0);
    sem_t *opened=sem_open("memory",0); CHECK(opened!=SEM_FAILED);
    CHECK(sem_wait(opened)==0 && sem_getvalue(mapped,&value)==0 && value==2);
    CHECK(sem_unlink("memory")==0 && close(fd)==0);
    CHECK(sem_post(mapped)==0 && sem_wait(opened)==0);
    CHECK(sem_close(opened)==0 && munmap(mapped,4096)==0);
}
#define THREADS 12
static sem_t *race_handles[THREADS];
static void *open_race(void *argument) {
    size_t index=(size_t)argument;
    race_handles[index]=sem_open("race",O_CREAT,0600,3U);
    CHECK(race_handles[index]!=SEM_FAILED);
    for(int i=0;i<100;i++) { sem_t *handle=sem_open("race",0); CHECK(handle==race_handles[index]); CHECK(sem_close(handle)==0); }
    return NULL;
}
static void races_and_fork(void) {
    pthread_t threads[THREADS];
    for(size_t i=0;i<THREADS;i++) CHECK(pthread_create(&threads[i],NULL,open_race,(void *)i)==0);
    for(int i=0;i<THREADS;i++) CHECK(pthread_join(threads[i],NULL)==0);
    for(int i=1;i<THREADS;i++) CHECK(race_handles[i]==race_handles[0] && sem_close(race_handles[i])==0);
    sem_t *handle=race_handles[0]; sem_t *another=sem_open("race",0); CHECK(another==handle);
    pid_t child=fork(); CHECK(child>=0);
    if(child==0) {
        CHECK(sem_close(another)==0 && sem_post(handle)==0 && sem_close(handle)==0);
        sem_t *fresh=sem_open("race",0); CHECK(fresh!=SEM_FAILED && sem_close(fresh)==0); _Exit(0);
    }
    child_ok(child); int value; CHECK(sem_getvalue(handle,&value)==0 && value==4);
    CHECK(sem_close(another)==0 && sem_close(handle)==0 && sem_unlink("race")==0);
    int gate[2]; CHECK(pipe(gate)==0); pid_t children[6];
    for(int i=0;i<6;i++) {
        children[i]=fork(); CHECK(children[i]>=0);
        if(children[i]==0) { char token; CHECK(read(gate[0],&token,1)==1); sem_t *s=sem_open("process-race",O_CREAT,0600,4U); CHECK(s!=SEM_FAILED); CHECK(sem_post(s)==0 && sem_close(s)==0); _Exit(0); }
    }
    CHECK(write(gate[1],"123456",6)==6);
    for(int i=0;i<6;i++) child_ok(children[i]);
    CHECK(close(gate[0])==0 && close(gate[1])==0);
    handle=sem_open("process-race",0); CHECK(handle!=SEM_FAILED);
    CHECK(sem_getvalue(handle,&value)==0 && value==10);
    CHECK(sem_close(handle)==0 && sem_unlink("process-race")==0);
}
static void saturation_and_reuse(void) {
    sem_t *handles[256]; char name[32];
    for(int i=0;i<300;i++) { errno=0; CHECK(sem_open("absent",0)==SEM_FAILED && errno==ENOENT); }
    for(int i=0;i<256;i++) { snprintf(name,sizeof name,"capacity-%d",i); handles[i]=sem_open(name,O_CREAT|O_EXCL,0600,0U); CHECK(handles[i]!=SEM_FAILED); }
    errno=0; CHECK(sem_open("capacity-extra",O_CREAT|O_EXCL,0600,0U)==SEM_FAILED && errno==EMFILE);
    errno=0; CHECK(sem_open("capacity-0",0)==SEM_FAILED && errno==EMFILE);
    bad_name("a/b",EINVAL);
    CHECK(sem_close(handles[255])==0);
    sem_t *duplicate=sem_open("capacity-0",0); CHECK(duplicate==handles[0] && sem_close(duplicate)==0);
    for(int i=0;i<256;i++) { snprintf(name,sizeof name,"capacity-%d",i); CHECK(sem_unlink(name)==0); if(i<255) CHECK(sem_close(handles[i])==0); }
    sem_t *reuse=sem_open("capacity-reuse",O_CREAT|O_EXCL,0600,0U);
    CHECK(reuse!=SEM_FAILED && sem_unlink("capacity-reuse")==0 && sem_close(reuse)==0);
}
static int cancellation_completed;
static void *pending_cancel(void *unused) {
    (void)unused; CHECK(pthread_cancel(pthread_self())==0);
    sem_t *handle=sem_open("cancel-sem",O_CREAT|O_EXCL,0600,1U);
    CHECK(handle!=SEM_FAILED && sem_close(handle)==0 && sem_unlink("cancel-sem")==0);
    int fd=shm_open("cancel-shm",O_CREAT|O_EXCL|O_RDWR,0600); CHECK(fd>=0);
    CHECK(shm_unlink("cancel-shm")==0);
    /* close is itself a cancellation point; disable around descriptor cleanup. */
    int previous; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&previous)==0);
    CHECK(close(fd)==0); CHECK(pthread_setcancelstate(previous,NULL)==0);
    cancellation_completed=1; pthread_testcancel(); CHECK(0); return NULL;
}
static _Atomic int waiter_tid;
static int waiter_cleaned;
static sem_t *blocked_sem;
static void clean_waiter(void *unused) { (void)unused; waiter_cleaned=1; }
static void *blocked_wait(void *unused) {
    (void)unused;
    pthread_cleanup_push(clean_waiter,NULL);
    atomic_store(&waiter_tid,(int)syscall(SYS_gettid));
    CHECK(sem_wait(blocked_sem)==0); CHECK(0);
    pthread_cleanup_pop(0);
    return NULL;
}
static void blocked_cancellation(void) {
    blocked_sem=sem_open("blocked",O_CREAT|O_EXCL,0600,0U); CHECK(blocked_sem!=SEM_FAILED);
    pthread_t thread; CHECK(pthread_create(&thread,NULL,blocked_wait,NULL)==0);
    int witnessed=0;
    for(int i=0;i<3000 && !witnessed;i++) {
        int tid=atomic_load(&waiter_tid);
        if(tid) {
            char path[96],line[256]; snprintf(path,sizeof path,"/proc/self/task/%d/syscall",tid);
            int fd=owned_cancellation_open_proc(path);
            if(fd>=0) {
                ssize_t n=read(fd,line,sizeof line-1); CHECK(close(fd)==0);
                if(n>0) { line[n]=0; long number=-1; unsigned long address=0,operation=0;
                    witnessed=sscanf(line,"%ld %lx %lx",&number,&address,&operation)==3
                        && number==SYS_futex && address==(unsigned long)blocked_sem && operation==0;
                }
            }
        }
        if(!witnessed) { const struct timespec delay={0,1000000}; nanosleep(&delay,NULL); }
    }
    CHECK(witnessed && pthread_cancel(thread)==0);
    void *result; CHECK(pthread_join(thread,&result)==0 && result==PTHREAD_CANCELED && waiter_cleaned);
    CHECK(sem_post(blocked_sem)==0 && sem_wait(blocked_sem)==0);
    CHECK(sem_close(blocked_sem)==0 && sem_unlink("blocked")==0);
}
static _Atomic int forking_run, forking_ready;
static void *open_during_fork(void *unused) {
    (void)unused; atomic_store(&forking_ready,1);
    while(atomic_load(&forking_run)) { sem_t *s=sem_open("fork-race",0); CHECK(s!=SEM_FAILED && sem_close(s)==0); }
    return NULL;
}
static void contended_fork(void) {
    sem_t *pinned=sem_open("fork-race",O_CREAT|O_EXCL,0600,0U); CHECK(pinned!=SEM_FAILED);
    atomic_store(&forking_run,1); pthread_t thread;
    CHECK(pthread_create(&thread,NULL,open_during_fork,NULL)==0);
    while(!atomic_load(&forking_ready)) sched_yield();
    for(int i=0;i<16;i++) {
        pid_t child=fork(); CHECK(child>=0);
        if(!child) { sem_t *s=sem_open("fork-race",0); CHECK(s!=SEM_FAILED); CHECK(sem_post(s)==0 && sem_close(s)==0); _Exit(0); }
        child_ok(child);
    }
    atomic_store(&forking_run,0); CHECK(pthread_join(thread,NULL)==0);
    int value; CHECK(sem_getvalue(pinned,&value)==0 && value==16);
    CHECK(sem_close(pinned)==0 && sem_unlink("fork-race")==0);
}
/* Process-local seccomp makes mapping failure repeatable after the table is
 * allocated. More than 256 failed creates must release every reservation and
 * temporary inode, without publishing a partly initialized object. */
static void failed_mapping_cleanup(void) {
    pid_t child=fork(); CHECK(child>=0);
    if(!child) {
        struct filter { unsigned short code; unsigned char jt,jf; unsigned int k; };
        struct filter filters[]={ {0x20,0,0,0}, {0x15,0,1,SYS_mmap},
            {0x06,0,0,0x00050000U|EPERM}, {0x06,0,0,0x7fff0000U} };
        struct program { unsigned short count; struct filter *instructions; } program={4,filters};
        CHECK(syscall(SYS_prctl,38,1L,0L,0L,0L)==0);
        CHECK(syscall(SYS_prctl,22,2L,&program,0L,0L)==0);
        for(int i=0;i<300;i++) {
            errno=0; CHECK(sem_open("mapping-failure",O_CREAT|O_EXCL,0600,0U)==SEM_FAILED && errno==EPERM);
            errno=0; CHECK(shm_open("mapping-failure",O_RDONLY,0)==-1 && errno==ENOENT);
        }
        _Exit(0);
    }
    child_ok(child);
}
int main(void) {
    namespace_rules(); shared_namespace_and_lifetime(); races_and_fork(); saturation_and_reuse();
    contended_fork(); blocked_cancellation(); failed_mapping_cleanup();
    pthread_t thread; void *result; CHECK(pthread_create(&thread,NULL,pending_cancel,NULL)==0);
    CHECK(pthread_join(thread,&result)==0 && result==PTHREAD_CANCELED && cancellation_completed==1);
    puts("owned-named-ipc-ok");
}
