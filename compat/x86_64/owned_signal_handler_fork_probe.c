#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <threads.h>
#include <stdint.h>
#include <time.h>

static volatile sig_atomic_t called, child_pid, fork_error;
static int raw, direct, queued;
static void handler(int signal) {
    (void)signal;
    errno=0;
    pid_t child=raw ? (pid_t)syscall(SYS_fork) : fork();
    if(child==0) _exit(0);
    fork_error=errno; child_pid=child; called=1;
}
static void *worker(void *unused) {
    (void)unused;
    if(queued) { while(!called) ; }
    else if(direct) handler(0);
    else if(raise(SIGUSR1)) return (void *)1;
    if(!called) return (void *)2;
    if(child_pid>0) {
        int status=-1;
        if(waitpid(child_pid,&status,0)!=child_pid || status!=0) return (void *)3;
    }
    return NULL;
}
static uint64_t callback_mask;
static void *observe_mask(void *unused) {
    (void)unused;
    if(syscall(SYS_rt_sigprocmask,SIG_SETMASK,NULL,&callback_mask,8)) _exit(20);
    return NULL;
}
static int observe_c11_mask(void *unused) { observe_mask(unused);return 0; }
static int mask_case(const char *mode) {
    /* Musl first-create setup unblocks its internal signals. Measure creation
       after that one-time runtime initialization. */
    pthread_t warmup;
    if(pthread_create(&warmup,NULL,observe_mask,NULL) || pthread_join(warmup,NULL))return 19;
    uint64_t original,requested,before,after;
    if(syscall(SYS_rt_sigprocmask,SIG_SETMASK,NULL,&original,8))return 21;
    requested=(original | (UINT64_C(1)<<(SIGUSR2-1)) | (UINT64_C(1)<<31) | (UINT64_C(1)<<32)) & ~(UINT64_C(1)<<(SIGUSR1-1));
    if(syscall(SYS_rt_sigprocmask,SIG_SETMASK,&requested,NULL,8) || syscall(SYS_rt_sigprocmask,SIG_SETMASK,NULL,&before,8))return 22;
    int failure=!strcmp(mode,"clone-failure");
    if(failure) {
        struct filter { unsigned short code;unsigned char yes,no;unsigned value; } instructions[]={
            {0x20,0,0,0},{0x15,0,1,SYS_clone},{0x06,0,0,0x50000|EAGAIN},{0x06,0,0,0x7fff0000}};
        struct { unsigned short count;struct filter *instructions; } program={4,instructions};
        if(syscall(SYS_prctl,38,1,0,0,0) || syscall(SYS_prctl,22,2,&program,0,0))return 23;
    }
    int c11=!strcmp(mode,"c11-mask");
    if(c11) {
        thrd_t thread;int result=-1;
        if(thrd_create(&thread,observe_c11_mask,NULL)!=thrd_success || thrd_join(thread,&result)!=thrd_success || result)return 24;
    } else {
        pthread_attr_t attributes;pthread_attr_t *selected=NULL;
        if(!strcmp(mode,"explicit-mask")) {
            if(pthread_attr_init(&attributes) || pthread_attr_setinheritsched(&attributes,PTHREAD_EXPLICIT_SCHED))return 25;
            selected=&attributes;
        }
        pthread_t thread=(pthread_t)(uintptr_t)0x1234;errno=123;
        int error=pthread_create(&thread,selected,observe_mask,NULL);
        if(errno!=123)return 26;
        if(failure) { if(error!=EAGAIN || thread!=(pthread_t)(uintptr_t)0x1234)return 27; }
        else { if(error || pthread_join(thread,NULL))return 28; }
        if(selected && pthread_attr_destroy(selected))return 29;
    }
    if(syscall(SYS_rt_sigprocmask,SIG_SETMASK,NULL,&after,8) || after!=before)return 30;
    if(!failure) {
        uint64_t expected=c11?(before | UINT64_C(0xfffffffc7fffffff)):(before & ~(UINT64_C(1)<<32));
        expected &= ~((UINT64_C(1)<<(SIGKILL-1)) | (UINT64_C(1)<<(SIGSTOP-1)));
        if(callback_mask!=expected)return 31;
    }
    if(syscall(SYS_rt_sigprocmask,SIG_SETMASK,&original,NULL,8))return 32;
    printf("mask=%s parent-restored=1 callback-ready=%d\n",mode,!failure);
    return 0;
}
/* A pthread_kill targeting a thread that is inside fork must not wait for
   that fork: musl's pthread_kill takes only the target's kill lock, never the
   thread-list lock that fork holds across its syscall. A seccomp listener
   parks the target's raw fork at syscall entry, so the forking thread holds
   every fork-transaction lock while an already-created sender signals it. */
static volatile int fork_listener=-1, kill_go, kill_done, kill_result=-1;
static pthread_t fork_target;
static void *fork_under_listener(void *unused) {
    (void)unused;
    struct filter { unsigned short code;unsigned char yes,no;unsigned value; } instructions[]={
        {0x20,0,0,0},{0x15,0,1,SYS_fork},{0x06,0,0,0x7fc00000},{0x06,0,0,0x7fff0000}};
    struct { unsigned short count;struct filter *instructions; } program={4,instructions};
    if(syscall(SYS_prctl,38,1,0,0,0)) _exit(40);
    long listener=syscall(SYS_seccomp,1,8,&program);
    if(listener<0) _exit(41);
    fork_listener=(int)listener;
    pid_t child=fork();
    if(child==0) _exit(0);
    int status=-1;
    if(child<0 || waitpid(child,&status,0)!=child || status!=0) return (void *)1;
    return NULL;
}
static void *kill_forking_target(void *unused) {
    (void)unused;
    while(!kill_go) ;
    kill_result=pthread_kill(fork_target,0);
    kill_done=1;
    return NULL;
}
static int kill_during_fork_case(void) {
    pthread_t sender;
    if(pthread_create(&sender,NULL,kill_forking_target,NULL))return 42;
    if(pthread_create(&fork_target,NULL,fork_under_listener,NULL))return 43;
    while(fork_listener<0) ;
    struct { uint64_t id;uint32_t pid,flags;int nr;uint32_t arch;uint64_t pc,args[6]; } notification;
    memset(&notification,0,sizeof notification);
    if(syscall(SYS_ioctl,fork_listener,0xc0502100UL,&notification) || notification.nr!=SYS_fork)return 44;
    kill_go=1;
    struct timespec pause={0,1000000};
    for(int waited=0;waited<2000 && !kill_done;waited++) nanosleep(&pause,NULL);
    int completed_while_forking=kill_done;
    struct { uint64_t id;int64_t value;int32_t error;uint32_t flags; } response={notification.id,0,0,1};
    if(syscall(SYS_ioctl,fork_listener,0xc0182101UL,&response))return 45;
    void *result;
    if(pthread_join(sender,&result) || result || pthread_join(fork_target,&result) || result)return 46;
    printf("kill-during-fork completed-while-forking=%d result=%d\n",completed_while_forking,kill_result);
    return completed_while_forking && !kill_result ? 0 : 47;
}
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    if(strstr(argv[1],"mask") || !strcmp(argv[1],"clone-failure"))return mask_case(argv[1]);
    if(!strcmp(argv[1],"kill-during-fork"))return kill_during_fork_case();
    raw=!strcmp(argv[1],"raw") || !strcmp(argv[1],"queued-raw");direct=!strcmp(argv[1],"direct");
    queued=!strcmp(argv[1],"queued") || !strcmp(argv[1],"queued-raw");
    struct rlimit limit;if(getrlimit(RLIMIT_NPROC,&limit)) return 3;
    printf("uid=%u euid=%u nproc=%llu,%llu\n",getuid(),geteuid(),(unsigned long long)limit.rlim_cur,(unsigned long long)limit.rlim_max);
    struct sigaction action={0};action.sa_handler=handler;sigemptyset(&action.sa_mask);
    if(sigaction(SIGUSR1,&action,NULL)) return 4;
    if(queued) {
        cpu_set_t allowed,selected;CPU_ZERO(&allowed);CPU_ZERO(&selected);
        if(sched_getaffinity(0,sizeof allowed,&allowed)) return 8;
        int cpu;for(cpu=0;cpu<CPU_SETSIZE && !CPU_ISSET(cpu,&allowed);cpu++);
        if(cpu==CPU_SETSIZE)return 9;
        CPU_SET(cpu,&selected);if(sched_setaffinity(0,sizeof selected,&selected))return 10;
    }
    int failed=0;
    for(int iteration=0;iteration<(queued?32:1);iteration++) {
        called=0;child_pid=0;fork_error=0;
        pthread_t thread;int error=pthread_create(&thread,NULL,worker,NULL);if(error) return 5;
        if(queued && pthread_kill(thread,SIGUSR1))return 11;
        void *result;if(pthread_join(thread,&result)||result) return 6;
        printf("iteration=%d called=%d child=%s errno=%d\n",iteration,called,child_pid>0?"created":"failed",fork_error);
        failed+=child_pid<=0;
    }
    return failed?7:0;
}
