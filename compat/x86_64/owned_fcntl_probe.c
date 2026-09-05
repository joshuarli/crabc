#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "owned_cancellation_proc_witness.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"owned-fcntl:%d: %s errno=%d\n",__LINE__,#x,errno); _Exit(95); } } while (0)
/* A legal two-argument caller deliberately leaves a hostile third register.
 * The public ABI must not turn this into a required Rust argument. */
extern int poisoned_query(int, int);
__asm__(".text\n.globl poisoned_query\n.hidden poisoned_query\n.type poisoned_query,@function\npoisoned_query:\nmovabs $0xa5a5a5a5a5a5a5a5,%rdx\njmp fcntl\n.size poisoned_query,.-poisoned_query\n");
static long raw_fcntl(int fd,int cmd,uintptr_t word) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(SYS_fcntl),"D"((long)fd),"S"((long)cmd),"d"(word) : "rcx","r11","memory","cc");
    return result;
}
static void raw_equivalent(long raw,int result) {
    if(result!=(raw<0 ? -1 : raw)) fprintf(stderr,"raw=%ld result=%d\n",raw,result);
    CHECK(result==(raw<0 ? -1 : raw));
    CHECK(errno==(raw<0 ? -raw : 77));
}
static void query(int fd,int cmd) {
    long raw=raw_fcntl(fd,cmd,0); errno=77;
    raw_equivalent(raw,poisoned_query(fd,cmd));
}
static void scalar(int fd,int cmd,int value) {
    long raw=raw_fcntl(fd,cmd,(uintptr_t)(long)value); errno=77;
    int result=fcntl(fd,cmd,value);
    if(result!=(raw<0 ? -1 : raw)) fprintf(stderr,"scalar cmd=%d value=%d\n",cmd,value);
    raw_equivalent(raw,result);
}
static void hint(int fd,int cmd,uint64_t value) {
    uint64_t expected=value, actual=value;
    long raw=raw_fcntl(fd,cmd,(uintptr_t)&expected); errno=77;
    raw_equivalent(raw,fcntl(fd,cmd,&actual));
    CHECK(actual==expected);
}
static struct flock whole(short type) {
    struct flock lock={.l_type=type,.l_whence=SEEK_SET,.l_start=0,.l_len=0};
    return lock;
}
static volatile sig_atomic_t notified;
static void notification(int signal) { notified=signal; }
static void basic(const char *path,int directory) {
    int p[2]; CHECK(pipe2(p,O_CLOEXEC)==0);
    query(p[0],F_GETFD); query(p[0],F_GETFL); query(p[0],F_GETPIPE_SZ);
    CHECK(fcntl(p[0],F_GETPIPE_SZ)>=4096);
    int duplicate=fcntl(p[0],F_DUPFD,40); CHECK(duplicate>=40 && fcntl(duplicate,F_GETFD)==0);
    int cloexec=fcntl(p[0],F_DUPFD_CLOEXEC,50); CHECK(cloexec>=50 && fcntl(cloexec,F_GETFD)==FD_CLOEXEC);
    CHECK(fcntl(duplicate,F_SETFL,O_NONBLOCK)==0 && (fcntl(p[0],F_GETFL)&O_NONBLOCK));
    CHECK(fcntl(p[0],F_GETFD)==FD_CLOEXEC && fcntl(duplicate,F_GETFD)==0);
    scalar(p[0],F_SETPIPE_SZ,4096); CHECK(fcntl(p[0],F_GETPIPE_SZ)==4096);
    CHECK(fcntl(p[0],F_SETOWN,-getpgrp())==0); errno=77;
    CHECK(poisoned_query(p[0],F_GETOWN)==-getpgrp() && errno==77);
    struct f_owner_ex owner={.type=F_OWNER_PID,.pid=getpid()}, got={0};
    CHECK(fcntl(p[0],F_SETOWN_EX,&owner)==0 && fcntl(p[0],F_GETOWN_EX,&got)==0);
    CHECK(got.type==F_OWNER_PID && got.pid==getpid() && fcntl(p[0],F_GETOWN)==getpid());
    owner.type=F_OWNER_PGRP; owner.pid=getpgrp();
    CHECK(fcntl(p[0],F_SETOWN_EX,&owner)==0); errno=77;
    CHECK(fcntl(p[0],F_GETOWN)==-getpgrp() && errno==77);
    uid_t expected[2]={123,456}, actual[2]={123,456};
    long raw=raw_fcntl(p[0],F_GETOWNER_UIDS,(uintptr_t)expected); errno=77;
    raw_equivalent(raw,fcntl(p[0],F_GETOWNER_UIDS,actual)); CHECK(!memcmp(actual,expected,sizeof actual));
    struct sigaction action={.sa_handler=notification}, previous;
    sigemptyset(&action.sa_mask); CHECK(sigaction(SIGUSR1,&action,&previous)==0);
    sigset_t notification_mask, previous_mask; sigemptyset(&notification_mask); sigaddset(&notification_mask,SIGUSR1);
    CHECK(pthread_sigmask(SIG_UNBLOCK,&notification_mask,&previous_mask)==0);
    CHECK(fcntl(p[0],F_SETOWN,getpid())==0 && fcntl(p[0],F_SETSIG,SIGUSR1)==0);
    query(p[0],F_GETSIG); CHECK(fcntl(p[0],F_GETSIG)==SIGUSR1);
    int flags=fcntl(p[0],F_GETFL); CHECK(fcntl(p[0],F_SETFL,flags|O_ASYNC)==0);
    CHECK(write(p[1],"N",1)==1);
    for(int i=0;i<3000 && !notified;i++) { const struct timespec delay={0,1000000}; nanosleep(&delay,NULL); }
    CHECK(notified==SIGUSR1 && fcntl(p[0],F_SETFL,flags)==0);
    char byte; CHECK(read(p[0],&byte,1)==1 && byte=='N');
    CHECK(fcntl(p[0],F_SETSIG,0)==0 && sigaction(SIGUSR1,&previous,NULL)==0);
    CHECK(pthread_sigmask(SIG_SETMASK,&previous_mask,NULL)==0);
    errno=77; CHECK(fcntl(p[0],F_DUPFD,-1)==-1 && errno==EINVAL);
    errno=77; CHECK(fcntl(p[0],F_DUPFD_CLOEXEC,-1)==-1 && errno==EINVAL);
    errno=77; CHECK(fcntl(p[0],F_GETOWN_EX,(void *)1)==-1 && errno==EFAULT);
    query(-1,F_GETFD); query(-1,F_GETOWN); query(p[0],-1); query(-1,-1);
    scalar(-1,F_SETPIPE_SZ,4096); scalar(-1,F_DUPFD,0);
    CHECK(close(duplicate)==0 && close(cloexec)==0 && close(p[0])==0 && close(p[1])==0);

    int fd=open(path,O_CREAT|O_TRUNC|O_RDWR|O_CLOEXEC,0600); CHECK(fd>=0);
    query(fd,F_GETLEASE);
    raw=raw_fcntl(fd,F_SETLEASE,F_WRLCK);
    if(raw==0) CHECK(raw_fcntl(fd,F_SETLEASE,F_UNLCK)==0);
    errno=77; raw_equivalent(raw,fcntl(fd,F_SETLEASE,F_WRLCK)); query(fd,F_GETLEASE);
    if(raw==0) CHECK(fcntl(fd,F_SETLEASE,F_UNLCK)==0);
    scalar(fd,F_SETLEASE,F_UNLCK);
    /* Register no events; DN_MULTISHOT exercises the unsigned long mask
     * without delivering signals or observing unrelated directories. */
    raw=raw_fcntl(directory,F_NOTIFY,DN_MULTISHOT); errno=77;
    raw_equivalent(raw,fcntl(directory,F_NOTIFY,(unsigned long)DN_MULTISHOT));
    hint(fd,F_SET_RW_HINT,RWH_WRITE_LIFE_SHORT); hint(fd,F_GET_RW_HINT,0);
    hint(fd,F_SET_FILE_RW_HINT,RWH_WRITE_LIFE_LONG); hint(fd,F_GET_FILE_RW_HINT,0);
    hint(fd,F_SET_RW_HINT,UINT64_MAX);
    struct flock canceled=whole(F_UNLCK); raw=raw_fcntl(fd,F_CANCELLK,(uintptr_t)&canceled); errno=77;
    raw_equivalent(raw,fcntl(fd,F_CANCELLK,&canceled));
    CHECK(close(fd)==0);
    fd=memfd_create("owned-fcntl-seals",MFD_CLOEXEC|MFD_ALLOW_SEALING); CHECK(fd>=0);
    CHECK(ftruncate(fd,4096)==0); query(fd,F_GET_SEALS); CHECK(fcntl(fd,F_GET_SEALS)==0);
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_GROW|F_SEAL_SHRINK)==0);
    CHECK(fcntl(fd,F_GET_SEALS)==(F_SEAL_GROW|F_SEAL_SHRINK));
    CHECK(ftruncate(fd,8192)==-1 && errno==EPERM);
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_SEAL)==0);
    CHECK(write(fd,"x",1)==-1 && errno==EPERM);
    CHECK(fcntl(fd,F_ADD_SEALS,F_SEAL_FUTURE_WRITE)==-1 && errno==EPERM);
    CHECK(close(fd)==0);
}
struct waiter { int fd,command; atomic_int tid,returned,cleaned; int result,error; };
static void unlock(void *arg) {
    struct waiter *w=arg; struct flock lock=whole(F_UNLCK);
    CHECK(fcntl(w->fd,w->command==F_OFD_SETLKW ? F_OFD_SETLK : F_SETLK,&lock)==0);
    atomic_store(&w->cleaned,1);
}
static void *waiter(void *arg) {
    struct waiter *w=arg; struct flock lock=whole(F_WRLCK);
    pthread_cleanup_push(unlock,w);
    atomic_store(&w->tid,(int)syscall(SYS_gettid)); errno=77;
    w->result=fcntl(w->fd,w->command,&lock); w->error=errno;
    atomic_store(&w->returned,1);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    return (void *)12;
}
static void wait_in_fcntl(struct waiter *w) {
    for(int i=0;i<3000;i++) {
        int tid=atomic_load(&w->tid);
        if(tid) {
            char path[96],line[256]; snprintf(path,sizeof path,"/proc/self/task/%d/syscall",tid);
            int fd=owned_cancellation_open_proc(path);
            if(fd>=0) { ssize_t n=read(fd,line,sizeof line-1); CHECK(close(fd)==0);
                if(n>0) { line[n]=0; long number=-1; unsigned long descriptor=0,cmd=0;
                    if(sscanf(line,"%ld %lx %lx",&number,&descriptor,&cmd)==3 && number==SYS_fcntl && descriptor==(unsigned)w->fd && cmd==(unsigned)w->command) return;
                }
            }
        }
        const struct timespec delay={0,1000000}; nanosleep(&delay,NULL);
    }
    CHECK(0);
}
static void ofd_locks(const char *path,int cancel) {
    int owner=open(path,O_RDWR|O_CLOEXEC), peer=open(path,O_RDWR|O_CLOEXEC); CHECK(owner>=0 && peer>=0);
    struct flock lock=whole(F_WRLCK); CHECK(fcntl(owner,F_OFD_SETLK,&lock)==0);
    lock=whole(F_WRLCK); CHECK(fcntl(peer,F_OFD_GETLK,&lock)==0 && lock.l_type==F_WRLCK && lock.l_pid==-1);
    lock=whole(F_WRLCK); CHECK(fcntl(peer,F_GETLK,&lock)==0 && lock.l_type==F_WRLCK && lock.l_pid==-1);
    lock=whole(F_WRLCK); CHECK(fcntl(peer,F_OFD_SETLK,&lock)==-1 && errno==EAGAIN);
    int retained=fcntl(owner,F_DUPFD_CLOEXEC,0); CHECK(retained>=0 && close(owner)==0);
    struct waiter w={.fd=peer,.command=F_OFD_SETLKW}; pthread_t t; CHECK(pthread_create(&t,NULL,waiter,&w)==0);
    wait_in_fcntl(&w);
    if(cancel) {
        CHECK(pthread_cancel(t)==0);
        /* This blocking Linux extension is not a musl cancellation point. */
        wait_in_fcntl(&w); CHECK(!atomic_load(&w.returned) && !atomic_load(&w.cleaned));
    }
    CHECK(close(retained)==0);
    void *result=NULL; CHECK(pthread_join(t,&result)==0);
    CHECK(result==(cancel ? PTHREAD_CANCELED : (void *)12));
    CHECK(atomic_load(&w.returned) && atomic_load(&w.cleaned) && w.result==0 && w.error==77);
    lock=whole(F_WRLCK); CHECK(fcntl(peer,F_OFD_GETLK,&lock)==0 && lock.l_type==F_UNLCK);
    CHECK(close(peer)==0);
}
static void posix_locks(const char *path,int cancel) {
    int fd=open(path,O_RDWR|O_CLOEXEC), ready[2],release[2]; CHECK(fd>=0 && pipe(ready)==0 && pipe(release)==0);
    pid_t pid=fork(); CHECK(pid>=0);
    if(!pid) {
        alarm(15); close(ready[0]); close(release[1]);
        struct flock lock=whole(F_WRLCK); CHECK(fcntl(fd,F_SETLK,&lock)==0 && write(ready[1],"K",1)==1);
        char byte; CHECK(read(release[0],&byte,1)==1); _Exit(0);
    }
    CHECK(close(ready[1])==0 && close(release[0])==0); char byte;
    CHECK(read(ready[0],&byte,1)==1 && close(ready[0])==0);
    struct flock lock=whole(F_WRLCK); CHECK(fcntl(fd,F_GETLK,&lock)==0 && lock.l_type==F_WRLCK && lock.l_pid==pid);
    lock=whole(F_WRLCK); CHECK(fcntl(fd,F_SETLK,&lock)==-1 && errno==EAGAIN);
    struct waiter w={.fd=fd,.command=F_SETLKW}; pthread_t t; CHECK(pthread_create(&t,NULL,waiter,&w)==0);
    wait_in_fcntl(&w); void *result=NULL;
    if(cancel) {
        CHECK(pthread_cancel(t)==0 && pthread_join(t,&result)==0 && result==PTHREAD_CANCELED);
        CHECK(!atomic_load(&w.returned) && atomic_load(&w.cleaned));
        lock=whole(F_WRLCK); CHECK(fcntl(fd,F_GETLK,&lock)==0 && lock.l_type==F_WRLCK && lock.l_pid==pid);
    }
    CHECK(write(release[1],"K",1)==1 && close(release[1])==0);
    int status; CHECK(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==0);
    if(!cancel) { CHECK(pthread_join(t,&result)==0 && result==(void *)12); CHECK(atomic_load(&w.returned) && atomic_load(&w.cleaned) && w.result==0 && w.error==77); }
    CHECK(close(fd)==0);
}
int main(int argc,char **argv) {
    alarm(30); CHECK(argc==2 && mkdir(argv[1],0700)==0);
    int directory=open(argv[1],O_RDONLY|O_DIRECTORY|O_CLOEXEC); CHECK(directory>=0);
    char path[4096]; CHECK(snprintf(path,sizeof path,"%s/file",argv[1])<(int)sizeof path);
    basic(path,directory);
    for(int cancel=0;cancel<2;cancel++) { ofd_locks(path,cancel); posix_locks(path,cancel); }
    CHECK(close(directory)==0 && unlink(path)==0 && rmdir(argv[1])==0);
    puts("owned-fcntl-ok");
}
