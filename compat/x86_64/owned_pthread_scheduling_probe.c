#define _GNU_SOURCE
#include <pthread.h>
#include <threads.h>
#include <sched.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"pthread-scheduling:%d: %s errno=%d\n",__LINE__,#x,errno); _Exit(95); } } while (0)
static atomic_int ready, release_worker, callbacks, retired_tid;
static void target(pthread_t t) {
    int policy=-1; struct sched_param p={.sched_priority=-1};
    errno=77;
    CHECK(pthread_getschedparam(t,&policy,&p)==0 && policy==SCHED_OTHER && p.sched_priority==0);
    CHECK(errno==77);
    CHECK(pthread_setschedparam(t,SCHED_OTHER,&p)==0 && errno==77);
    CHECK(pthread_setschedprio(t,0)==0 && errno==77);
    CHECK(pthread_setschedprio(t,-1)==EINVAL && errno==77);
    CHECK(pthread_setschedparam(t,-1,&p)==EINVAL && errno==77);
}
static void *worker(void *arg) {
    atomic_fetch_add(&callbacks,1);
    target(pthread_self());
    sigset_t mask;
    CHECK(pthread_sigmask(SIG_SETMASK,NULL,&mask)==0);
    CHECK(sigismember(&mask,SIGUSR1)==(arg==(void *)2) && sigismember(&mask,SIGUSR2));
    if (arg) {
        pthread_attr_t a; size_t stack,guard;
        CHECK(pthread_getattr_np(pthread_self(),&a)==0);
        CHECK(pthread_attr_getstacksize(&a,&stack)==0 && stack>=262144);
        CHECK(pthread_attr_getguardsize(&a,&guard)==0 && guard==16384);
    }
    atomic_store(&ready,1);
    while (!atomic_load(&release_worker)) sched_yield();
    return arg;
}
static void *inherited_worker(void *arg) { return arg; }
static void *retired_worker(void *arg) { atomic_store(&retired_tid,(int)syscall(SYS_gettid)); return arg; }
static int c11(void *arg) { worker(arg); return 12; }
/* Process-local filter proves denied setup without acquiring privileged
 * scheduling or changing any host scheduling/rlimit configuration. */
struct filter { unsigned short code; unsigned char jt,jf; unsigned k; };
static void deny_scheduler(void) {
    struct filter f[]={{0x20,0,0,0},{0x15,0,1,SYS_sched_setscheduler},{0x06,0,0,0x50000|EPERM},{0x06,0,0,0x7fff0000}};
    struct { unsigned short len; struct filter *filter; } program={4,f};
    CHECK(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0);
    CHECK(prctl(PR_SET_SECCOMP,2,&program)==0);
}
/* Scope, concurrency, affinity, thread names, and C11 identity/exit. A
 * named thread's comm file is reached through /proc, which the dynamic cells'
 * chroot does not mount; musl then reports the open error, so the probe
 * requires success with /proc and ENOENT without it. */
static atomic_int named_ready, named_release;
static void *named_worker(void *arg) {
    atomic_store(&named_ready,1);
    while(!atomic_load(&named_release)) sched_yield();
    return arg;
}
static int c11_exit_worker(void *arg) {
    thrd_t *observed=arg;
    *observed=thrd_current();
    CHECK((thrd_equal)(thrd_current(),*observed));
    thrd_exit(33);
}
static tss_t surface_key;
static atomic_int detached_done;
static int c11_detached_worker(void *arg) {
    CHECK(tss_get(surface_key)==NULL && tss_set(surface_key,(void *)8)==thrd_success);
    atomic_store(&detached_done,(int)(intptr_t)tss_get(surface_key));
    return (int)(intptr_t)arg;
}
static int surface(void) {
    pthread_attr_t a; int scope=-1;
    errno=77;
    CHECK(pthread_attr_init(&a)==0);
    CHECK(pthread_attr_setscope(&a,PTHREAD_SCOPE_SYSTEM)==0);
    CHECK(pthread_attr_setscope(&a,PTHREAD_SCOPE_PROCESS)==ENOTSUP);
    CHECK(pthread_attr_setscope(&a,7)==EINVAL);
    CHECK(pthread_attr_getscope(&a,&scope)==0 && scope==PTHREAD_SCOPE_SYSTEM);
    CHECK(pthread_attr_destroy(&a)==0);
    CHECK(pthread_getconcurrency()==0);
    CHECK(pthread_setconcurrency(-1)==EINVAL && pthread_setconcurrency(3)==EAGAIN);
    CHECK(pthread_setconcurrency(0)==0 && pthread_getconcurrency()==0 && errno==77);

    cpu_set_t set, observed, empty;
    CPU_ZERO(&set); CPU_ZERO(&empty);
    CHECK(pthread_getaffinity_np(pthread_self(),sizeof set,&set)==0 && CPU_COUNT(&set)>0);
    CHECK(pthread_setaffinity_np(pthread_self(),sizeof set,&set)==0);
    CHECK(pthread_setaffinity_np(pthread_self(),sizeof empty,&empty)==EINVAL && errno==77);
    pthread_t t; void *result;
    CHECK(pthread_create(&t,NULL,named_worker,(void *)5)==0);
    while(!atomic_load(&named_ready)) sched_yield();
    memset(&observed,0xff,sizeof observed);
    CHECK(pthread_getaffinity_np(t,sizeof observed,&observed)==0 && CPU_EQUAL(&set,&observed));
    CHECK(pthread_setaffinity_np(t,sizeof set,&set)==0 && errno==77);

    char name[32];
    CHECK(pthread_setname_np(pthread_self(),"sixteen-bytes-xx")==ERANGE);
    CHECK(pthread_getname_np(pthread_self(),name,15)==ERANGE && errno==77);
    CHECK(pthread_setname_np(pthread_self(),"crabc-main")==0);
    CHECK(pthread_getname_np(pthread_self(),name,sizeof name)==0 && !strcmp(name,"crabc-main"));
    struct stat proc;
    if (stat("/proc/self/task",&proc)==0) {
        CHECK(pthread_setname_np(t,"crabc-worker")==0);
        CHECK(pthread_getname_np(t,name,sizeof name)==0 && !strcmp(name,"crabc-worker"));
    } else {
        CHECK(pthread_setname_np(t,"crabc-worker")==ENOENT);
        CHECK(pthread_getname_np(t,name,sizeof name)==ENOENT);
    }
    atomic_store(&named_release,1);
    CHECK(pthread_join(t,&result)==0 && result==(void *)5);

    thrd_t main_thread=thrd_current(), child, reported;
    int status=0;
    CHECK((thrd_equal)(main_thread,thrd_current()) && (thrd_equal)(main_thread,pthread_self()));
    CHECK(thrd_create(&child,c11_exit_worker,&reported)==thrd_success);
    CHECK(thrd_join(child,&status)==thrd_success && status==33);
    CHECK((thrd_equal)(child,reported) && !(thrd_equal)(child,main_thread));
    /* Explicit scheduling parameters round-trip through the attribute. */
    struct sched_param wanted={.sched_priority=0}, stored={.sched_priority=-1};
    CHECK(pthread_attr_init(&a)==0);
    CHECK(pthread_attr_setschedparam(&a,&wanted)==0 && pthread_attr_getschedparam(&a,&stored)==0);
    CHECK(stored.sched_priority==0);
    CHECK(pthread_attr_setinheritsched(&a,PTHREAD_EXPLICIT_SCHED)==0);
    CHECK(pthread_create(&t,&a,inherited_worker,(void *)6)==0 && pthread_join(t,&result)==0 && result==(void *)6);
    CHECK(pthread_attr_destroy(&a)==0);
    CHECK((pthread_equal)(pthread_self(),pthread_self()) && !(pthread_equal)(pthread_self(),t));

    /* A detached C11 thread publishes through TSS and finishes on its own. */
    CHECK(tss_create(&surface_key,NULL)==thrd_success);
    CHECK(tss_set(surface_key,(void *)7)==thrd_success && tss_get(surface_key)==(void *)7);
    CHECK(thrd_create(&child,c11_detached_worker,NULL)==thrd_success);
    CHECK(thrd_detach(child)==thrd_success);
    while(!atomic_load(&detached_done)) CHECK(thrd_sleep(&(struct timespec){.tv_nsec=1000000},NULL)==0);
    CHECK(atomic_load(&detached_done)==8 && tss_get(surface_key)==(void *)7);
    tss_delete(surface_key);
    CHECK(thrd_sleep(&(struct timespec){0},NULL)==0);
    errno=77;
    CHECK(thrd_sleep(&(struct timespec){.tv_nsec=-1},NULL)==-2 && errno==77);
    puts("pthread scope, concurrency, affinity, names, and C11 identity/exit: PASS");
    return 0;
}
int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1],"surface")) return surface();
    target(pthread_self());
    sigset_t inherited; sigemptyset(&inherited); sigaddset(&inherited,SIGUSR2);
    CHECK(pthread_sigmask(SIG_BLOCK,&inherited,NULL)==0);
    pthread_attr_t a; pthread_t t; void *result;
    CHECK(pthread_attr_init(&a)==0);
    CHECK(pthread_attr_setinheritsched(&a,PTHREAD_EXPLICIT_SCHED)==0);
    errno=77;
    CHECK(pthread_create(&t,&a,worker,NULL)==0 && errno==77);
    while(!atomic_load(&ready)) sched_yield();
    target(t); atomic_store(&release_worker,1); CHECK(pthread_join(t,&result)==0);
    CHECK(pthread_create(&t,NULL,retired_worker,NULL)==0);
    while(!atomic_load(&retired_tid)) sched_yield();
    while(syscall(SYS_tgkill,getpid(),atomic_load(&retired_tid),0)==0) sched_yield();
    CHECK(errno==ESRCH);
    int retired_policy=123; struct sched_param retired_param={.sched_priority=456};
    errno=77;
    CHECK(pthread_getschedparam(t,&retired_policy,&retired_param)==ESRCH && errno==77);
    CHECK(retired_policy==123 && retired_param.sched_priority==456);
    CHECK(pthread_setschedparam(t,-1,&retired_param)==ESRCH && errno==77);
    CHECK(pthread_setschedprio(t,-1)==ESRCH && errno==77);
    CHECK(pthread_join(t,&result)==0);
    int before=atomic_load(&callbacks);
    /* Failed creation must release every transient mapping before returning.
     * Each failed stack request is 1 MiB; 512 leaked requests exceed this
     * process-local address-space bound. No /proc mount is needed in chroot. */
    struct rlimit memory_limit={256UL*1024*1024,256UL*1024*1024};
    CHECK(setrlimit(RLIMIT_AS,&memory_limit)==0);
    CHECK(pthread_attr_setstacksize(&a,1024*1024)==0);
    CHECK(pthread_attr_setschedpolicy(&a,-1)==0);
    for(int i=0;i<512;i++) { t=(pthread_t)(uintptr_t)0x1234; errno=77;
        CHECK(pthread_attr_setdetachstate(&a,i%2)==0);
        CHECK(pthread_create(&t,&a,worker,NULL)==EINVAL && errno==77);
        CHECK(t==(pthread_t)(uintptr_t)0x1234 && atomic_load(&callbacks)==before);
    }
    void *caller_stack=mmap(NULL,1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(caller_stack!=MAP_FAILED);
    CHECK(pthread_attr_setstack(&a,caller_stack,1024*1024)==0);
    CHECK(pthread_create(&t,&a,worker,NULL)==EINVAL);
    unsigned char resident;
    CHECK(mincore(caller_stack,4096,&resident)==0);
    CHECK(munmap(caller_stack,1024*1024)==0);
    CHECK(pthread_attr_setstacksize(&a,1024*1024)==0);
    CHECK(pthread_attr_setschedpolicy(&a,SCHED_OTHER)==0);
    sigset_t after; CHECK(pthread_sigmask(SIG_SETMASK,NULL,&after)==0);
    CHECK(!sigismember(&after,SIGUSR1) && sigismember(&after,SIGUSR2));
    pid_t pid=fork(); CHECK(pid>=0);
    if(!pid) { deny_scheduler();
        for(int i=0;i<512;i++) { errno=77; CHECK(pthread_attr_setdetachstate(&a,i%2)==0); CHECK(pthread_create(&t,&a,worker,NULL)==EPERM && errno==77); CHECK(atomic_load(&callbacks)==before); }
        CHECK(pthread_attr_setinheritsched(&a,PTHREAD_INHERIT_SCHED)==0);
        CHECK(pthread_attr_setdetachstate(&a,PTHREAD_CREATE_JOINABLE)==0);
        CHECK(pthread_create(&t,&a,inherited_worker,NULL)==0 && pthread_join(t,&result)==0);
        _Exit(0);
    }
    int status; CHECK(waitpid(pid,&status,0)==pid && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(pthread_attr_init(&a)==0);
    CHECK(pthread_attr_setstacksize(&a,262144)==0 && pthread_attr_setguardsize(&a,16384)==0);
    CHECK(pthread_setattr_default_np(&a)==0);
    pthread_attr_t b; CHECK(pthread_getattr_default_np(&b)==0 && !memcmp(&a,&b,sizeof a));
    CHECK(pthread_attr_init(&b)==0 && !memcmp(&a,&b,sizeof a));
    CHECK(pthread_attr_setdetachstate(&b,PTHREAD_CREATE_DETACHED)==0);
    CHECK(pthread_setattr_default_np(&b)==EINVAL);
    CHECK(pthread_attr_init(&b)==0); CHECK(pthread_attr_setstack(&b,(void *)0x10000,262144)==0); CHECK(pthread_setattr_default_np(&b)==EINVAL);
    memset(&b,0,sizeof b); CHECK(pthread_setattr_default_np(&b)==0);
    CHECK(pthread_getattr_default_np(&b)==0 && !memcmp(&a,&b,sizeof a));
    CHECK(pthread_create(&t,NULL,worker,(void *)1)==0); CHECK(pthread_join(t,&result)==0 && result==(void *)1);
    thrd_t ct; int cr; CHECK(thrd_create(&ct,c11,(void *)2)==thrd_success); CHECK(thrd_join(ct,&cr)==thrd_success && cr==12);
    CHECK(pthread_attr_setstacksize(&a,16*1024*1024)==0 && pthread_attr_setguardsize(&a,2*1024*1024)==0);
    CHECK(pthread_setattr_default_np(&a)==0 && pthread_getattr_default_np(&b)==0);
    size_t stack,guard; CHECK(pthread_attr_getstacksize(&b,&stack)==0 && stack==8*1024*1024);
    CHECK(pthread_attr_getguardsize(&b,&guard)==0 && guard==1024*1024);
    puts("pthread scheduling/default attributes: PASS");
}
