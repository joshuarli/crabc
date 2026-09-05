#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include "owned_cancellation_proc_witness.h"

/* musl 1.2.6 src/signal/{sigtimedwait,sigwaitinfo,sigwait}.c:
 * all three spellings reach the same cancellation-point syscall; raw EINTR
 * retries without publishing errno. In particular sigwait retains musl's
 * -1/errno error result, and only writes its signal output after success. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"signal-wait-cancel:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
enum operation { TIMED_WAIT, INFO_WAIT, SIGNAL_WAIT };
struct wait_state {
    enum operation operation;
    int cancel_state, pending, signal;
    sigset_t mask;
    siginfo_t info;
    struct timespec timeout;
    _Atomic int tid, returned, result, error, state_after, cleanup, blocked_in_cleanup;
};
static void cleanup_waiter(void *opaque) {
    struct wait_state *s=opaque;
    sigset_t mask; if (pthread_sigmask(SIG_SETMASK,NULL,&mask)) _exit(81);
    atomic_store(&s->blocked_in_cleanup,sigismember(&mask,SIGUSR2));
    atomic_store(&s->cleanup,1);
}
static void *wait_worker(void *opaque) {
    struct wait_state *s=opaque;
    if (pthread_setcancelstate(s->cancel_state,NULL)) _exit(82);
    pthread_cleanup_push(cleanup_waiter,s);
    if (s->pending && pthread_cancel(pthread_self())) _exit(83);
    errno=90;
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    int result;
    switch (s->operation) {
    case TIMED_WAIT: result=sigtimedwait(&s->mask,&s->info,&s->timeout); break;
    case INFO_WAIT: result=sigwaitinfo(&s->mask,&s->info); break;
    case SIGNAL_WAIT: result=sigwait(&s->mask,&s->signal); break;
    default: _exit(84);
    }
    atomic_store(&s->result,result); atomic_store(&s->error,errno); atomic_store(&s->returned,1);
    int previous=-1; if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous)) _exit(85);
    atomic_store(&s->state_after,previous);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static int in_signal_wait(struct wait_state *s) {
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
                    if (sscanf(line,"%ld",&number)==1 && number==SYS_rt_sigtimedwait) return 1;
                }
            }
        }
        if (atomic_load(&s->returned)) return 0;
        nanosleep(&delay,NULL);
    }
    return 0;
}
static int queue_signal(void) {
    union sigval value={.sival_int=314}; CHECK(!sigqueue(getpid(),SIGUSR2,value)); return 0;
}
static void initialize_state(struct wait_state *s, enum operation op, int state, int pending) {
    memset(s,0,sizeof *s); s->operation=op; s->cancel_state=state; s->pending=pending;
    s->signal=0x12345678; s->state_after=-1; s->timeout=(struct timespec){10,123};
    sigemptyset(&s->mask); sigaddset(&s->mask,SIGUSR2); memset(&s->info,0x5a,sizeof s->info);
}
static int check_output(struct wait_state *s, int success) {
    if (!success) {
        siginfo_t original; memset(&original,0x5a,sizeof original);
        CHECK(!memcmp(&s->info,&original,sizeof original) && s->signal==0x12345678);
    } else if (s->operation==SIGNAL_WAIT) CHECK(s->signal==SIGUSR2);
    else CHECK(s->info.si_signo==SIGUSR2 && s->info.si_code==SI_QUEUE &&
        s->info.si_pid==getpid() && s->info.si_uid==getuid() && s->info.si_value.sival_int==314);
    CHECK(atomic_load(&s->cleanup) && atomic_load(&s->blocked_in_cleanup)==1);
    return 0;
}
static int pending_wait(enum operation op, int cancel_state, int timeout_kind) {
    struct wait_state s; initialize_state(&s,op,cancel_state,1);
    if (timeout_kind==1) s.timeout.tv_nsec=1000000000;
    if (timeout_kind==2) s.timeout=(struct timespec){0,0};
    int queued=timeout_kind!=2; if (queued) CHECK(!queue_signal());
    const struct timespec original_timeout=s.timeout;
    pthread_t thread; void *result=NULL; CHECK(!pthread_create(&thread,NULL,wait_worker,&s));
    CHECK(!pthread_join(thread,&result) && result==PTHREAD_CANCELED);
    int returned=cancel_state!=PTHREAD_CANCEL_ENABLE;
    int consumed=cancel_state==PTHREAD_CANCEL_DISABLE && timeout_kind==0;
    CHECK(atomic_load(&s.returned)==returned && !check_output(&s,consumed));
    CHECK(!memcmp(&s.timeout,&original_timeout,sizeof original_timeout));
    if (returned) {
        int expected_error=cancel_state==2 ? ECANCELED : timeout_kind==1 ? EINVAL : timeout_kind==2 ? EAGAIN : 90;
        CHECK(atomic_load(&s.error)==expected_error);
        CHECK(atomic_load(&s.result)==(consumed ? op==SIGNAL_WAIT ? 0 : SIGUSR2 : -1));
        CHECK(atomic_load(&s.state_after)==PTHREAD_CANCEL_DISABLE);
    }
    siginfo_t info; const struct timespec zero={0,0};
    int left=sigtimedwait(&s.mask,&info,&zero);
    if (queued && !consumed) CHECK(left==SIGUSR2 && info.si_value.sival_int==314);
    else CHECK(left==-1 && errno==EAGAIN);
    printf("signal pending operation=%d state=%d timeout=%d consumed=%d\n",op,cancel_state,timeout_kind,consumed);
    return 0;
}
static int blocked_wait(enum operation op, int cancel_state) {
    struct wait_state s; initialize_state(&s,op,cancel_state,0);
    pthread_t thread; void *result=NULL; CHECK(!pthread_create(&thread,NULL,wait_worker,&s));
    CHECK(in_signal_wait(&s) && !pthread_cancel(thread));
    int consumed=cancel_state==PTHREAD_CANCEL_DISABLE;
    if (consumed) { CHECK(in_signal_wait(&s)); CHECK(!queue_signal()); }
    CHECK(!pthread_join(thread,&result) && result==PTHREAD_CANCELED && !check_output(&s,consumed));
    CHECK(atomic_load(&s.returned)==(cancel_state!=PTHREAD_CANCEL_ENABLE));
    if (cancel_state!=PTHREAD_CANCEL_ENABLE) {
        CHECK(atomic_load(&s.error)==(consumed ? 90 : ECANCELED));
        CHECK(atomic_load(&s.result)==(consumed ? op==SIGNAL_WAIT ? 0 : SIGUSR2 : -1));
        CHECK(atomic_load(&s.state_after)==PTHREAD_CANCEL_DISABLE);
    }
    printf("signal blocked operation=%d state=%d consumed=%d\n",op,cancel_state,consumed);
    return 0;
}
static _Atomic int interrupted;
static void interrupt_handler(int number) { (void)number; atomic_store(&interrupted,1); }
static int retry_interruption(enum operation op) {
    struct wait_state s; initialize_state(&s,op,PTHREAD_CANCEL_ENABLE,0);
    pthread_t thread; CHECK(!pthread_create(&thread,NULL,wait_worker,&s)); CHECK(in_signal_wait(&s));
    atomic_store(&interrupted,0);
    CHECK(!syscall(SYS_tgkill,getpid(),atomic_load(&s.tid),SIGUSR1));
    while (!atomic_load(&interrupted)) {}
    CHECK(in_signal_wait(&s) && !atomic_load(&s.returned)); CHECK(!queue_signal());
    void *result=(void *)1; CHECK(!pthread_join(thread,&result) && result==NULL && !check_output(&s,1));
    CHECK(atomic_load(&s.result)==(op==SIGNAL_WAIT ? 0 : SIGUSR2) && atomic_load(&s.error)==90);
    printf("signal interrupted operation=%d retries-without-errno-mutation\n",op);
    return 0;
}
int main(void) {
    alarm(30);
    sigset_t blocked, old_mask; sigemptyset(&blocked); sigaddset(&blocked,SIGUSR2);
    CHECK(!pthread_sigmask(SIG_BLOCK,&blocked,&old_mask));
    for (int op=TIMED_WAIT;op<=SIGNAL_WAIT;op++) for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) {
        CHECK(!pending_wait(op,state,0) && !blocked_wait(op,state));
        if (op==TIMED_WAIT) CHECK(!pending_wait(op,state,1) && !pending_wait(op,state,2));
    }
    struct sigaction action={.sa_handler=interrupt_handler}, old_action;
    sigemptyset(&action.sa_mask); CHECK(!sigaction(SIGUSR1,&action,&old_action));
    for (int op=TIMED_WAIT;op<=SIGNAL_WAIT;op++) CHECK(!retry_interruption(op));
    CHECK(!sigaction(SIGUSR1,&old_action,NULL) && !pthread_sigmask(SIG_SETMASK,&old_mask,NULL));
    puts("owned-signal-wait-cancellation-ok");
    return 0;
}
