#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "owned_cancellation_proc_witness.h"

/* Residual process.signal evidence. The frozen helper/reporting spellings
 * remain owned by owned_signal_helpers_probe.c, and the three wait APIs'
 * cancellation behavior by owned_signal_wait_cancellation_probe.c. */
#define CHECK(x) do { if (!(x)) { dprintf(2,"signal-full:%d errno=%d\n",__LINE__,errno); _exit(1); } } while (0)
#define OBS(x) do { errno=90; long result=(x); int error=errno; printf("%s: result=%ld errno=%d\n",#x,result,error); } while (0)
static unsigned long word(const sigset_t *set) { unsigned long value; memcpy(&value,set,sizeof value); return value; }
static void tail(const sigset_t *set, unsigned char byte) {
    const unsigned char *bytes=(const unsigned char *)set;
    for (size_t i=sizeof(unsigned long); i<sizeof *set; i++) CHECK(bytes[i]==byte);
}
static void empty(sigset_t *set) { memset(set,0,sizeof *set); CHECK(!sigemptyset(set)); }
static void block_pair(void) {
    sigset_t set; empty(&set); CHECK(!sigaddset(&set,SIGUSR1)); CHECK(!sigaddset(&set,SIGUSR2));
    CHECK(!sigprocmask(SIG_SETMASK,&set,NULL));
}
static void sets(void) {
    sigset_t left,right,out;
    memset(&left,0xa5,sizeof left); OBS(sigemptyset(&left)); tail(&left,0xa5); CHECK(word(&left)==0);
    OBS(sigisemptyset(&left)); OBS(sigaddset(&left,SIGUSR1)); OBS(sigaddset(&left,64));
    OBS(sigismember(&left,SIGUSR1)); OBS(sigismember(&left,SIGUSR2)); OBS(sigisemptyset(&left));
    tail(&left,0xa5); CHECK(word(&left)==((1UL<<(SIGUSR1-1))|(1UL<<63)));
    memset(&right,0x5a,sizeof right); OBS(sigfillset(&right)); tail(&right,0x5a);
    CHECK(word(&right)==0xfffffffc7fffffffUL);
    memset(&out,0x37,sizeof out); OBS(sigandset(&out,&left,&right)); tail(&out,0x37); CHECK(word(&out)==word(&left));
    OBS(sigdelset(&right,SIGUSR1)); OBS(sigandset(&left,&left,&right)); CHECK(word(&left)==(1UL<<63));
    OBS(sigorset(&left,&right,&left)); CHECK(word(&left)==word(&right)); tail(&left,0xa5);
    OBS(sigorset(&out,&out,&out)); tail(&out,0x37);
    const int invalid[]={-1,0,32,33,34,65};
    for (size_t i=0;i<sizeof invalid/sizeof *invalid;i++) {
        int signal_number=invalid[i]; sigset_t before=left;
        printf("signal-number=%d\n",signal_number);
        OBS(sigaddset(&left,signal_number)); CHECK(!memcmp(&left,&before,sizeof left));
        OBS(sigdelset(&left,signal_number)); CHECK(!memcmp(&left,&before,sizeof left));
        OBS(sigismember(&left,signal_number));
    }
    OBS(__libc_current_sigrtmin()); OBS(__libc_current_sigrtmax());
    CHECK(SIGRTMIN==35 && SIGRTMAX==64);
}
static volatile sig_atomic_t calls;
static void handler(int signal_number) { if (signal_number==SIGUSR1) calls++; }
static void actions_masks(void) {
    errno=90; void (*old)(int)=signal(SIGUSR1,handler); int error=errno;
    printf("signal: previous-default=%d errno=%d\n",old==SIG_DFL,error); CHECK(old==SIG_DFL);
    struct sigaction action,queried; memset(&action,0,sizeof action);
    OBS(sigaction(SIGUSR1,NULL,&action)); CHECK(action.sa_handler==handler && (action.sa_flags&SA_RESTART));
    OBS(raise(SIGUSR1)); CHECK(calls==1);
    CHECK(!sigaddset(&action.sa_mask,SIGUSR2)); action.sa_flags|=SA_NODEFER;
    OBS(sigaction(SIGUSR1,&action,NULL));
    OBS(siginterrupt(SIGUSR1,1)); OBS(sigaction(SIGUSR1,NULL,&queried));
    CHECK(queried.sa_handler==handler && (queried.sa_flags&SA_NODEFER) && !(queried.sa_flags&SA_RESTART) && sigismember(&queried.sa_mask,SIGUSR2));
    OBS(siginterrupt(SIGUSR1,0)); OBS(sigaction(SIGUSR1,NULL,&queried)); CHECK(queried.sa_flags&SA_RESTART);
    const int invalid[]={0,32,33,34,65,SIGKILL,SIGSTOP};
    for (size_t i=0;i<sizeof invalid/sizeof *invalid;i++) {
        int signal_number=invalid[i]; printf("action-number=%d\n",signal_number);
        OBS(sigaction(signal_number,&action,NULL));
    }
    sigset_t set,before,after; empty(&set); memset(&before,0xa5,sizeof before);
    OBS(sigprocmask(SIG_SETMASK,&set,&before)); tail(&before,0xa5);
    OBS(sigprocmask(123,&set,NULL)); OBS(sigprocmask(123,NULL,&before)); tail(&before,0xa5);
    CHECK(!sigfillset(&set)); memset(&after,0x5a,sizeof after);
    OBS(sigprocmask(SIG_BLOCK,&set,NULL)); OBS(sigprocmask(SIG_SETMASK,NULL,&after)); tail(&after,0x5a);
    CHECK(word(&after)==(word(&set)&~((1UL<<(SIGKILL-1))|(1UL<<(SIGSTOP-1)))));
    OBS(sigprocmask(SIG_UNBLOCK,&set,NULL)); OBS(sigprocmask(SIG_SETMASK,NULL,&after)); CHECK(word(&after)==0);
    block_pair(); OBS(raise(SIGUSR1)); CHECK(calls==1);
    memset(&after,0x37,sizeof after); OBS(sigpending(&after)); tail(&after,0x37); CHECK(sigismember(&after,SIGUSR1));
    empty(&set); OBS(sigprocmask(SIG_SETMASK,&set,NULL)); CHECK(calls==2);
    OBS(sigpending(&after)); CHECK(!sigismember(&after,SIGUSR1));
}
static void queue_delivery(void) {
    sigset_t set; empty(&set); CHECK(!sigaddset(&set,SIGRTMIN)); CHECK(!sigaddset(&set,SIGRTMAX));
    CHECK(!sigprocmask(SIG_SETMASK,&set,NULL));
    union sigval value={.sival_int=111}; OBS(sigqueue(getpid(),SIGRTMIN,value));
    value.sival_int=222; OBS(sigqueue(getpid(),SIGRTMIN,value));
    value.sival_int=333; OBS(sigqueue(getpid(),SIGRTMAX,value));
    sigset_t pending; empty(&pending); OBS(sigpending(&pending)); CHECK(sigismember(&pending,SIGRTMIN) && sigismember(&pending,SIGRTMAX));
    for (int i=0;i<3;i++) {
        siginfo_t info; memset(&info,0x5a,sizeof info); struct timespec zero={0,0};
        errno=90; int result=sigtimedwait(&set,&info,&zero),error=errno;
        printf("queued: result=%d errno=%d signal=%d code=%d sender=%d uid=%d value=%d\n",result,error,info.si_signo,info.si_code,info.si_pid==getpid(),info.si_uid==getuid(),info.si_value.sival_int);
        CHECK(result==(i==2?SIGRTMAX:SIGRTMIN) && info.si_code==SI_QUEUE && info.si_pid==getpid() && info.si_uid==getuid() && info.si_value.sival_int==(i+1)*111);
    }
    struct timespec zero={0,0}; OBS(sigtimedwait(&set,NULL,&zero));
    OBS(sigqueue(getpid(),65,value)); OBS(kill(getpid(),65)); OBS(killpg(-1,0)); OBS(kill(getpid(),0));
    int channel[2]; CHECK(!pipe(channel)); pid_t parent=getpid(),child=fork(); CHECK(child>=0);
    if (!child) {
        CHECK(!close(channel[0]) && setsid()==getpid()); alarm(5);
        empty(&set); CHECK(!sigaddset(&set,SIGUSR1) && !sigprocmask(SIG_SETMASK,&set,NULL));
        CHECK(write(channel[1],"R",1)==1 && !close(channel[1]));
        siginfo_t info; errno=90; int result=sigwaitinfo(&set,&info),error=errno;
        printf("group-delivery: result=%d errno=%d code=%d parent=%d\n",result,error,info.si_code,info.si_pid==parent);
        CHECK(result==SIGUSR1 && info.si_code==SI_USER && info.si_pid==parent); _exit(0);
    }
    CHECK(!close(channel[1])); char ready; CHECK(read(channel[0],&ready,1)==1 && ready=='R' && !close(channel[0]));
    errno=90; int result=killpg(child,SIGUSR1),error=errno,status;
    CHECK(waitpid(child,&status,0)==child); printf("killpg: result=%d errno=%d child-status=%d\n",result,error,status); CHECK(!result && status==0);
}
static void suspend_delivery(void) {
    CHECK(signal(SIGUSR1,handler)!=SIG_ERR); block_pair(); CHECK(!raise(SIGUSR1));
    OBS(sigpause(SIGUSR1)); CHECK(calls==1);
    sigset_t mask; empty(&mask); CHECK(!sigprocmask(SIG_SETMASK,NULL,&mask));
    CHECK(sigismember(&mask,SIGUSR1) && sigismember(&mask,SIGUSR2));
    CHECK(!raise(SIGUSR1)); CHECK(!sigdelset(&mask,SIGUSR1)); OBS(sigsuspend(&mask)); CHECK(calls==2);
    CHECK(!sigprocmask(SIG_SETMASK,NULL,&mask)); CHECK(sigismember(&mask,SIGUSR1) && sigismember(&mask,SIGUSR2));
    const int invalid[]={0,32,33,34,65};
    for (size_t i=0;i<sizeof invalid/sizeof *invalid;i++) { int signal_number=invalid[i]; printf("pause-number=%d\n",signal_number); OBS(sigpause(signal_number)); }
}
struct cancel_state { int pause,pending,disabled; _Atomic int tid,returned,cleanup; int result,error,mask1,mask2; };
static void cleanup_suspend(void *opaque) {
    struct cancel_state *state=opaque; sigset_t mask; empty(&mask); CHECK(!pthread_sigmask(SIG_SETMASK,NULL,&mask));
    state->mask1=sigismember(&mask,SIGUSR1); state->mask2=sigismember(&mask,SIGUSR2); atomic_store(&state->cleanup,1);
}
static void *suspend_worker(void *opaque) {
    struct cancel_state *state=opaque; block_pair(); sigset_t temporary; empty(&temporary); CHECK(!sigaddset(&temporary,SIGUSR2));
    CHECK(!pthread_setcancelstate(state->disabled?PTHREAD_CANCEL_DISABLE:PTHREAD_CANCEL_ENABLE,NULL));
    pthread_cleanup_push(cleanup_suspend,state);
    if (state->pending) { CHECK(!raise(SIGUSR1)); CHECK(!pthread_cancel(pthread_self())); }
    errno=90; atomic_store(&state->tid,(int)syscall(SYS_gettid));
    state->result=state->pause?sigpause(SIGUSR1):sigsuspend(&temporary); state->error=errno; atomic_store(&state->returned,1);
    CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL)); pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static void witness_suspend(struct cancel_state *state) {
    const struct timespec delay={0,1000000};
    for (int attempt=0;attempt<2000;attempt++) {
        int tid=atomic_load(&state->tid);
        if (tid) {
            char path[96],buffer[128]; snprintf(path,sizeof path,"/proc/self/task/%d/syscall",tid);
            int fd=owned_cancellation_open_proc(path); CHECK(fd>=0); ssize_t count=read(fd,buffer,sizeof buffer-1); CHECK(!close(fd));
            if (count>0) { buffer[count]=0; long number=-1; if (sscanf(buffer,"%ld",&number)==1 && number==SYS_rt_sigsuspend) return; }
        }
        CHECK(!atomic_load(&state->returned)); CHECK(!nanosleep(&delay,NULL));
    }
    CHECK(0);
}
static void suspend_cancellation(int pause) {
    CHECK(signal(SIGUSR1,handler)!=SIG_ERR);
    for (int kind=0;kind<3;kind++) {
        struct cancel_state state={.pause=pause,.pending=kind!=2,.disabled=kind==1}; pthread_t thread;
        CHECK(!pthread_create(&thread,NULL,suspend_worker,&state));
        if (!state.pending) { witness_suspend(&state); CHECK(!pthread_cancel(thread)); }
        void *result; CHECK(!pthread_join(thread,&result));
        printf("suspend-cancel: pause=%d kind=%d canceled=%d returned=%d cleanup=%d mask=%d,%d result=%d errno=%d\n",pause,kind,result==PTHREAD_CANCELED,atomic_load(&state.returned),atomic_load(&state.cleanup),state.mask1,state.mask2,state.result,state.error);
        CHECK(result==PTHREAD_CANCELED && atomic_load(&state.cleanup));
    }
}
static void deny_futex_interrupt(void) {
    struct instruction { unsigned short code; unsigned char yes,no; unsigned value; };
    struct program { unsigned short count; struct instruction *instructions; };
    struct instruction instructions[]={{0x20,0,0,0},{0x15,0,1,SYS_futex},{0x06,0,0,0x00050000|EINTR},{0x06,0,0,0x7fff0000}};
    struct program program={sizeof instructions/sizeof *instructions,instructions};
    CHECK(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)); CHECK(!syscall(SYS_seccomp,1,0,&program));
}
static void interrupt_bookkeeping(void) {
    CHECK(signal(SIGUSR1,handler)!=SIG_ERR); OBS(siginterrupt(SIGUSR1,1));
    sem_t semaphore; CHECK(!sem_init(&semaphore,0,0)); struct timespec deadline; CHECK(!clock_gettime(CLOCK_REALTIME,&deadline));
    deadline.tv_nsec+=20000000; if (deadline.tv_nsec>=1000000000) { deadline.tv_sec++; deadline.tv_nsec-=1000000000; }
    deny_futex_interrupt(); OBS(sem_timedwait(&semaphore,&deadline)); CHECK(!sem_destroy(&semaphore));
}
static unsigned char alternate[65536] __attribute__((aligned(16)));
static volatile sig_atomic_t on_alternate,onstack_flag,disable_result,disable_error;
static void alternate_handler(int signal_number) {
    (void)signal_number; volatile unsigned char local; uintptr_t address=(uintptr_t)&local;
    on_alternate=address>=(uintptr_t)alternate && address<(uintptr_t)alternate+sizeof alternate;
    stack_t current; CHECK(!sigaltstack(NULL,&current)); onstack_flag=!!(current.ss_flags&SS_ONSTACK);
    stack_t disabled={.ss_flags=SS_DISABLE}; errno=90; disable_result=sigaltstack(&disabled,NULL); disable_error=errno;
}
static void alternate_stack(int minimum_only) {
    stack_t request={.ss_sp=alternate,.ss_size=minimum_only?2048:sizeof alternate},old;
    if (minimum_only) {
        OBS(sigaltstack(&request,NULL)); request.ss_flags=SS_DISABLE; CHECK(!sigaltstack(&request,NULL));
        request.ss_flags=SS_ONSTACK; OBS(sigaltstack(&request,NULL)); return;
    }
    OBS(sigaltstack(NULL,&old)); CHECK(old.ss_flags&SS_DISABLE);
    request.ss_size=0; OBS(sigaltstack(&request,NULL)); request.ss_flags=SS_ONSTACK; OBS(sigaltstack(&request,NULL));
    request.ss_size=sizeof alternate; OBS(sigaltstack(&request,NULL)); request.ss_flags=4; OBS(sigaltstack(&request,NULL));
    request.ss_flags=0; OBS(sigaltstack(&request,&old)); CHECK(old.ss_flags&SS_DISABLE);
    OBS(sigaltstack(NULL,&old)); CHECK(old.ss_sp==alternate && old.ss_size==sizeof alternate && old.ss_flags==0);
    struct sigaction action; memset(&action,0,sizeof action); action.sa_handler=alternate_handler; action.sa_flags=SA_ONSTACK; empty(&action.sa_mask);
    CHECK(!sigaction(SIGUSR1,&action,NULL)); CHECK(!raise(SIGUSR1));
    printf("alternate-handler: entered=%d onstack=%d disable-result=%d disable-errno=%d\n",on_alternate,onstack_flag,disable_result,disable_error);
    CHECK(on_alternate && onstack_flag && disable_result==-1 && disable_error==EPERM);
    request.ss_flags=SS_DISABLE; OBS(sigaltstack(&request,&old)); CHECK(old.ss_sp==alternate && old.ss_flags==0);
    OBS(sigaltstack(NULL,&old)); CHECK(old.ss_flags&SS_DISABLE);
}
static void signal_descriptor(void) {
    sigset_t set,other; empty(&set); empty(&other); CHECK(!sigaddset(&set,SIGRTMIN)); CHECK(!sigaddset(&other,SIGUSR2));
    sigset_t both; empty(&both); CHECK(!sigorset(&both,&set,&other)); CHECK(!sigprocmask(SIG_SETMASK,&both,NULL));
    errno=90; int fd=signalfd(-1,&set,SFD_CLOEXEC|SFD_NONBLOCK),error=errno;
    printf("signalfd-create: result=%d errno=%d\n",fd,error); CHECK(fd>=0);
    CHECK((fcntl(fd,F_GETFD)&FD_CLOEXEC) && (fcntl(fd,F_GETFL)&O_NONBLOCK));
    struct signalfd_siginfo info; OBS(read(fd,&info,sizeof info));
    union sigval value={.sival_int=123}; CHECK(!sigqueue(getpid(),SIGRTMIN,value));
    OBS(read(fd,&info,sizeof info-1)); OBS(read(fd,&info,sizeof info));
    printf("signalfd-info: signal=%u code=%d sender=%d uid=%d value=%d\n",info.ssi_signo,info.ssi_code,info.ssi_pid==(unsigned)getpid(),info.ssi_uid==getuid(),info.ssi_int);
    CHECK(info.ssi_signo==(unsigned)SIGRTMIN && info.ssi_code==SI_QUEUE && info.ssi_int==123);
    OBS(signalfd(fd,&other,0)); value.sival_int=456; CHECK(!sigqueue(getpid(),SIGUSR2,value));
    OBS(read(fd,&info,sizeof info)); CHECK(info.ssi_signo==SIGUSR2 && info.ssi_int==456);
    value.sival_int=789; CHECK(!sigqueue(getpid(),SIGRTMIN,value)); OBS(read(fd,&info,sizeof info));
    OBS(signalfd(fd,&set,1)); OBS(signalfd(-2,&set,0));
    int channel[2]; CHECK(!pipe(channel)); OBS(signalfd(channel[0],&set,0)); CHECK(!close(channel[0]) && !close(channel[1]));
    OBS(signalfd(fd,&set,0)); OBS(read(fd,&info,sizeof info)); CHECK(info.ssi_signo==(unsigned)SIGRTMIN && info.ssi_int==789);
    CHECK(!close(fd));
}
int main(int argc,char **argv) {
    CHECK(argc==2); CHECK(!setvbuf(stdout,NULL,_IONBF,0));
    sigset_t baseline; empty(&baseline); CHECK(!sigprocmask(SIG_SETMASK,&baseline,NULL));
    if (!strcmp(argv[1],"sets")) sets();
    else if (!strcmp(argv[1],"actions-masks")) actions_masks();
    else if (!strcmp(argv[1],"queue-delivery")) queue_delivery();
    else if (!strcmp(argv[1],"suspend-delivery")) suspend_delivery();
    else if (!strcmp(argv[1],"sigpause-cancellation")) suspend_cancellation(1);
    else if (!strcmp(argv[1],"sigsuspend-cancellation")) suspend_cancellation(0);
    else if (!strcmp(argv[1],"interrupt-bookkeeping")) interrupt_bookkeeping();
    else if (!strcmp(argv[1],"alternate-stack")) alternate_stack(0);
    else if (!strcmp(argv[1],"alternate-minimum")) alternate_stack(1);
    else if (!strcmp(argv[1],"signalfd")) signal_descriptor();
    else CHECK(0);
    puts("owned-posix-signals-ok"); return 0;
}
