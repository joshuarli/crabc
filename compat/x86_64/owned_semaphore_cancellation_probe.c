#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include "owned_cancellation_proc_witness.h"

/* musl 1.2.6 src/thread/sem_{init,getvalue,trywait,wait,timedwait,post}.c,
 * __timedwait.c, and src/signal/sigaction.c define this contract. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"semaphore-cancel:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
struct wait_state {
    sem_t *sem;
    int timed, cancel_state, pending, hold;
    struct timespec deadline;
    _Atomic int tid, returned, result, error, state_after, cleanup, cleanup_waiters, finish;
};
static int waiters(sem_t *sem) {
    /* Observe the fixed source ABI's advisory count atomically. User cleanup
     * must run only after the semaphore's internal cleanup withdrew its hint. */
    return __atomic_load_n(((int *)sem)+1,__ATOMIC_ACQUIRE);
}
static struct timespec after_milliseconds(long ms) {
    struct timespec at;
    if (clock_gettime(CLOCK_REALTIME,&at)) _exit(91);
    at.tv_nsec+=ms*1000000;
    at.tv_sec+=at.tv_nsec/1000000000;
    at.tv_nsec%=1000000000;
    return at;
}
static void cleanup_waiter(void *opaque) {
    struct wait_state *s=opaque;
    atomic_store(&s->cleanup_waiters,waiters(s->sem));
    atomic_store(&s->cleanup,1);
}
static void *wait_worker(void *opaque) {
    struct wait_state *s=opaque;
    if (pthread_setcancelstate(s->cancel_state,NULL)) _exit(92);
    pthread_cleanup_push(cleanup_waiter,s);
    if (s->pending && pthread_cancel(pthread_self())) _exit(93);
    errno=90;
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    int result=s->timed ? sem_timedwait(s->sem,&s->deadline) : sem_wait(s->sem);
    atomic_store(&s->result,result); atomic_store(&s->error,errno);
    atomic_store(&s->returned,1);
    while (s->hold && !atomic_load(&s->finish)) {}
    int previous=-1;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous)) _exit(94);
    atomic_store(&s->state_after,previous);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static int in_futex(struct wait_state *s) {
    const struct timespec delay={0,1000000};
    for (int retry=0;retry<2000;retry++) {
        int tid=atomic_load(&s->tid);
        if (tid) {
            char path[96], line[256];
            snprintf(path,sizeof path,"/proc/self/task/%d/syscall",tid);
            int fd=owned_cancellation_open_proc(path);
            if (fd>=0) {
                ssize_t count=read(fd,line,sizeof line-1); close(fd);
                if (count>0) {
                    line[count]=0; long number=-1;
                    if (sscanf(line,"%ld",&number)==1 && number==SYS_futex && waiters(s->sem)>0) return 1;
                }
            }
        }
        if (atomic_load(&s->returned)) return 0;
        nanosleep(&delay,NULL);
    }
    return 0;
}
static int assert_tokens(sem_t *sem, int expected) {
    int value=-1; CHECK(!sem_getvalue(sem,&value) && value==expected && waiters(sem)==0);
    for (int i=0;i<expected;i++) CHECK(!sem_trywait(sem));
    CHECK(sem_trywait(sem)==-1 && errno==EAGAIN);
    return 0;
}
static int pending_wait(int timed, int cancel_state, unsigned tokens, int deadline_kind) {
    sem_t sem; CHECK(!sem_init(&sem,0,tokens));
    struct wait_state s={.sem=&sem,.timed=timed,.cancel_state=cancel_state,.pending=1,
        .deadline=after_milliseconds(30000),.state_after=-1,.cleanup_waiters=-1};
    if (deadline_kind==1) s.deadline.tv_nsec=-1;
    if (deadline_kind==2) s.deadline=(struct timespec){0,0};
    pthread_t thread; void *result=NULL; CHECK(!pthread_create(&thread,NULL,wait_worker,&s));
    CHECK(!pthread_join(thread,&result) && result==PTHREAD_CANCELED && atomic_load(&s.cleanup));
    int returned=cancel_state!=PTHREAD_CANCEL_ENABLE;
    CHECK(atomic_load(&s.returned)==returned && atomic_load(&s.cleanup_waiters)==0);
    int consumed=returned && tokens>0;
    if (returned) {
        int expected_result=consumed ? 0 : -1;
        int expected_error=consumed ? 90 : deadline_kind==1 ? EINVAL : deadline_kind==2 ? ETIMEDOUT : ECANCELED;
        int expected_state=cancel_state==2 && !tokens && !deadline_kind ? PTHREAD_CANCEL_DISABLE : cancel_state;
        CHECK(atomic_load(&s.result)==expected_result && atomic_load(&s.error)==expected_error);
        CHECK(atomic_load(&s.state_after)==expected_state);
    }
    CHECK(!assert_tokens(&sem,tokens-consumed) && !sem_destroy(&sem));
    printf("semaphore pending timed=%d state=%d tokens=%u deadline=%d\n",timed,cancel_state,tokens,deadline_kind);
    return 0;
}
static int blocked_wait(int timed, int cancel_state, int shared) {
    sem_t *sem=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0); CHECK(sem!=MAP_FAILED);
    CHECK(!sem_init(sem,shared,0));
    struct wait_state s={.sem=sem,.timed=timed,.cancel_state=cancel_state,
        .deadline=after_milliseconds(30000),.state_after=-1,.cleanup_waiters=-1};
    pthread_t thread; void *result=NULL; CHECK(!pthread_create(&thread,NULL,wait_worker,&s));
    CHECK(in_futex(&s));
    int value=-1; CHECK(!sem_getvalue(sem,&value) && value==0);
    CHECK(!pthread_cancel(thread));
    if (cancel_state==PTHREAD_CANCEL_DISABLE) { CHECK(in_futex(&s)); CHECK(!sem_post(sem)); }
    CHECK(!pthread_join(thread,&result) && result==PTHREAD_CANCELED && atomic_load(&s.cleanup));
    CHECK(atomic_load(&s.cleanup_waiters)==0 && !assert_tokens(sem,0));
    CHECK(atomic_load(&s.returned)==(cancel_state!=PTHREAD_CANCEL_ENABLE));
    if (cancel_state==PTHREAD_CANCEL_DISABLE)
        CHECK(atomic_load(&s.result)==0 && atomic_load(&s.error)==EAGAIN);
    if (cancel_state==2)
        CHECK(atomic_load(&s.result)==-1 && atomic_load(&s.error)==ECANCELED && atomic_load(&s.state_after)==PTHREAD_CANCEL_DISABLE);
    CHECK(!sem_post(sem) && !assert_tokens(sem,1));
    CHECK(!sem_destroy(sem) && !munmap(sem,4096));
    printf("semaphore blocked timed=%d state=%d shared=%d cleanup-before-user\n",timed,cancel_state,shared);
    return 0;
}
static int multiple_waiters(int shared) {
    sem_t sem; CHECK(!sem_init(&sem,shared,0));
    struct wait_state states[3]; pthread_t threads[3];
    memset(states,0,sizeof states);
    for (int i=0;i<3;i++) {
        states[i].sem=&sem; states[i].timed=1; states[i].deadline=after_milliseconds(30000);
        CHECK(!pthread_create(&threads[i],NULL,wait_worker,&states[i]) && in_futex(&states[i]));
    }
    CHECK(waiters(&sem)==3 && !pthread_cancel(threads[1]));
    void *result=NULL; CHECK(!pthread_join(threads[1],&result) && result==PTHREAD_CANCELED);
    CHECK(atomic_load(&states[1].cleanup_waiters)==2 && waiters(&sem)==2);
    CHECK(!sem_post(&sem) && !sem_post(&sem));
    CHECK(!pthread_join(threads[0],&result) && result==NULL && !atomic_load(&states[0].result));
    CHECK(!pthread_join(threads[2],&result) && result==NULL && !atomic_load(&states[2].result));
    CHECK(!assert_tokens(&sem,0) && !sem_destroy(&sem));
    printf("semaphore multiple waiters shared=%d cancel-one/post-two conserves tokens\n",shared);
    return 0;
}
static int elapsed_timeout(int shared) {
    sem_t sem; CHECK(!sem_init(&sem,shared,0));
    struct wait_state s={.sem=&sem,.timed=1,.deadline=after_milliseconds(30),.cleanup_waiters=-1};
    pthread_t thread; CHECK(!pthread_create(&thread,NULL,wait_worker,&s));
    CHECK(!pthread_join(thread,NULL));
    CHECK(atomic_load(&s.returned) && atomic_load(&s.result)==-1 && atomic_load(&s.error)==ETIMEDOUT);
    CHECK(atomic_load(&s.cleanup_waiters)==0 && !assert_tokens(&sem,0) && !sem_destroy(&sem));
    printf("semaphore elapsed timeout shared=%d withdraws waiter\n",shared);
    return 0;
}
static int token_races(void) {
    for (int cancel=0;cancel<=1;cancel++) for (int i=0;i<64;i++) {
        sem_t sem; CHECK(!sem_init(&sem,i&1,0));
        struct wait_state s={.sem=&sem,.timed=1,.hold=1,.deadline=after_milliseconds(cancel ? 30000 : 2),.cleanup_waiters=-1};
        pthread_t thread; void *result=NULL; CHECK(!pthread_create(&thread,NULL,wait_worker,&s));
        if (cancel) CHECK(in_futex(&s));
        else {
            while (!atomic_load(&s.tid)) {}
            if (i&1) { const struct timespec delay={0,3000000}; nanosleep(&delay,NULL); }
        }
        CHECK(!sem_post(&sem));
        if (cancel) CHECK(!pthread_cancel(thread));
        atomic_store(&s.finish,1);
        CHECK(!pthread_join(thread,&result));
        CHECK(result==(cancel ? PTHREAD_CANCELED : NULL));
        CHECK(atomic_load(&s.cleanup) && atomic_load(&s.cleanup_waiters)==0);
        int consumed=atomic_load(&s.returned) && atomic_load(&s.result)==0;
        if (!cancel && !consumed) CHECK(atomic_load(&s.error)==ETIMEDOUT);
        CHECK(!assert_tokens(&sem,1-consumed) && !sem_destroy(&sem));
    }
    puts("semaphore post/cancel and post/timeout races conserve tokens");
    return 0;
}
static _Atomic int handled;
static void signal_handler(int number) { (void)number; atomic_store(&handled,1); }
static int signal_wait(int restart, int sticky) {
    struct sigaction action={.sa_handler=signal_handler,.sa_flags=restart ? SA_RESTART : 0}, old;
    sigemptyset(&action.sa_mask); CHECK(!sigaction(SIGUSR1,&action,&old));
    sem_t sem; CHECK(!sem_init(&sem,0,0));
    struct wait_state s={.sem=&sem,.timed=1,.deadline=after_milliseconds(30000),.cleanup_waiters=-1};
    pthread_t thread; CHECK(!pthread_create(&thread,NULL,wait_worker,&s)); CHECK(in_futex(&s));
    atomic_store(&handled,0); CHECK(!syscall(SYS_tgkill,getpid(),atomic_load(&s.tid),SIGUSR1));
    while (!atomic_load(&handled)) {}
    if (!sticky) { CHECK(in_futex(&s)); CHECK(!sem_post(&sem)); }
    CHECK(!pthread_join(thread,NULL));
    CHECK(atomic_load(&s.returned) && atomic_load(&s.cleanup_waiters)==0);
    CHECK(atomic_load(&s.result)==(sticky ? -1 : 0));
    CHECK(atomic_load(&s.error)==(sticky ? EINTR : EAGAIN));
    CHECK(!assert_tokens(&sem,0) && !sem_destroy(&sem) && !sigaction(SIGUSR1,&old,NULL));
    printf("semaphore timed signal restart=%d sticky-interrupting=%d\n",restart,sticky);
    return 0;
}
static int failed_handler_install(void) {
    /* SIGKILL passes musl's public signal-number validation; the kernel then
     * rejects it. Source bookkeeping happens before that rejected syscall. */
    struct sigaction action={.sa_handler=signal_handler,.sa_flags=0};
    sigemptyset(&action.sa_mask); CHECK(sigaction(SIGKILL,&action,NULL)==-1 && errno==EINVAL);
    CHECK(!signal_wait(1,1));
    return 0;
}
static int shared_process(void) {
    sem_t *sem=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0); CHECK(sem!=MAP_FAILED);
    CHECK(!sem_init(sem,1,0));
    pid_t child=fork(); CHECK(child>=0);
    if (!child) {
        struct timespec at=after_milliseconds(30000);
        if (sem_timedwait(sem,&at)) _exit(95);
        _exit(23);
    }
    const struct timespec delay={0,1000000};
    for (int retry=0;retry<2000 && !waiters(sem);retry++) nanosleep(&delay,NULL);
    CHECK(waiters(sem)==1 && !sem_post(sem));
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==23);
    CHECK(!assert_tokens(sem,0) && !sem_destroy(sem) && !munmap(sem,4096));
    puts("semaphore shared process wake conserves token");
    return 0;
}
static int value_errors(void) {
    sem_t sem, original; memset(&sem,0x5a,sizeof sem); memcpy(&original,&sem,sizeof sem);
    errno=90; CHECK(sem_init(&sem,0,UINT_MAX)==-1 && errno==EINVAL && !memcmp(&sem,&original,sizeof sem));
    CHECK(!sem_init(&sem,0,SEM_VALUE_MAX));
    errno=90; CHECK(sem_post(&sem)==-1 && errno==EOVERFLOW);
    int value=-1; CHECK(!sem_getvalue(&sem,&value) && value==SEM_VALUE_MAX && !sem_destroy(&sem));
    CHECK(!sem_init(&sem,0,0));
    struct timespec invalid={0,1000000000};
    CHECK(sem_timedwait(&sem,&invalid)==-1 && errno==EINVAL && waiters(&sem)==0);
    invalid=(struct timespec){0,0};
    CHECK(sem_timedwait(&sem,&invalid)==-1 && errno==ETIMEDOUT && waiters(&sem)==0);
    CHECK(!sem_destroy(&sem));
    puts("semaphore init/post overflow and timed validation preserve state");
    return 0;
}
int main(void) {
    alarm(30);
    CHECK(!pending_wait(0,PTHREAD_CANCEL_ENABLE,1,0));
    for (int timed=0;timed<=1;timed++) for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) {
        CHECK(!pending_wait(timed,state,1,0));
        if (state!=PTHREAD_CANCEL_DISABLE) CHECK(!pending_wait(timed,state,0,0));
        if (timed) for (int kind=1;kind<=2;kind++) {
            CHECK(!pending_wait(timed,state,1,kind)); CHECK(!pending_wait(timed,state,0,kind));
        }
        for (int shared=0;shared<=1;shared++) CHECK(!blocked_wait(timed,state,shared));
    }
    for (int shared=0;shared<=1;shared++) CHECK(!multiple_waiters(shared) && !elapsed_timeout(shared));
    CHECK(!value_errors() && !token_races() && !shared_process());
    /* Ignored/default dispositions and public-invalid signal numbers must
     * not set the source's sticky real-handler bookkeeping. */
    struct sigaction ignored={.sa_handler=SIG_IGN}, previous;
    sigemptyset(&ignored.sa_mask); CHECK(!sigaction(SIGUSR2,&ignored,&previous));
    ignored.sa_handler=SIG_DFL; CHECK(!sigaction(SIGUSR2,&ignored,NULL));
    ignored.sa_handler=signal_handler;
    CHECK(sigaction(0,&ignored,NULL)==-1 && errno==EINVAL);
    CHECK(!sigaction(SIGUSR2,&previous,NULL));
    /* No interrupting handler has been installed in this fresh process. */
    CHECK(!signal_wait(1,0));
    pid_t child=fork(); CHECK(child>=0);
    if (!child) _exit(failed_handler_install());
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    CHECK(!signal_wait(0,1));
    CHECK(!signal_wait(1,1));
    puts("owned-semaphore-cancellation-ok");
    return 0;
}
