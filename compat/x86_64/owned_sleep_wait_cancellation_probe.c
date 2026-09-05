#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <threads.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/resource.h>

/* Pinned musl 1.2.6 time/nanosleep.c, time/clock_nanosleep.c,
 * unistd/{sleep,usleep}.c, thread/thrd_sleep.c, process/{wait,waitpid,waitid}.c,
 * and linux/{wait3,wait4}.c define this split. Linux wait3/wait4 extensions
 * deliberately remain non-canceling, unlike POSIX wait/waitpid/waitid. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"sleep-wait-cancel:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
enum sleep_operation { NANO_SLEEP, CLOCK_RELATIVE, CLOCK_ABSOLUTE, SECONDS_SLEEP, MICRO_SLEEP, C11_SLEEP, REJECT_CPU_CLOCK };
struct sleep_state {
    enum sleep_operation operation;
    int cancel_state, blocked;
    struct timespec request, remaining;
    _Atomic int tid, returned, result, error, state_after, cleanup;
};
static void sleep_cleanup(void *opaque) { struct sleep_state *s=opaque; atomic_store(&s->cleanup,1); }
static void *sleep_worker(void *opaque) {
    struct sleep_state *s=opaque;
    if (pthread_setcancelstate(s->cancel_state,NULL)) _exit(61);
    pthread_cleanup_push(sleep_cleanup,s);
    if (!s->blocked && pthread_cancel(pthread_self())) _exit(62);
    errno=90;
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    int result;
    switch(s->operation) {
    case NANO_SLEEP: result=nanosleep(&s->request,&s->remaining); break;
    case CLOCK_RELATIVE: result=clock_nanosleep(CLOCK_REALTIME,0,&s->request,&s->remaining); break;
    case CLOCK_ABSOLUTE: result=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&s->request,&s->remaining); break;
    case SECONDS_SLEEP: result=sleep(s->request.tv_sec); break;
    case MICRO_SLEEP: result=usleep(s->request.tv_sec*1000000); break;
    case C11_SLEEP: result=thrd_sleep(&s->request,&s->remaining); break;
    case REJECT_CPU_CLOCK: result=clock_nanosleep(CLOCK_THREAD_CPUTIME_ID,0,&s->request,&s->remaining); break;
    default: _exit(63);
    }
    atomic_store(&s->result,result); atomic_store(&s->error,errno); atomic_store(&s->returned,1);
    int previous=-1;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous)) _exit(64);
    atomic_store(&s->state_after,previous);
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return (void *)1;
}
static int wait_in_syscall(_Atomic int *target_tid, long expected) {
    const struct timespec pause={0,1000000};
    for (int retry=0;retry<2000;retry++) {
        int tid=atomic_load(target_tid);
        if (tid) {
            char path[96], line[256];
            snprintf(path,sizeof path,"/proc/self/task/%d/syscall",tid);
            int fd=open(path,O_RDONLY|O_CLOEXEC);
            if (fd>=0) {
                ssize_t count=read(fd,line,sizeof line-1); close(fd);
                if (count>0) {
                    line[count]=0; long actual=-1;
                    if (sscanf(line,"%ld",&actual)==1 && actual==expected) return 1;
                }
            }
        }
        nanosleep(&pause,NULL);
    }
    return 0;
}
static int exercise_sleep(enum sleep_operation operation, int cancel_state, int blocked) {
    struct sleep_state state={.operation=operation,.cancel_state=cancel_state,.blocked=blocked,
        .request={blocked ? 30 : cancel_state==PTHREAD_CANCEL_DISABLE ? 0 : 3,0},.remaining={123,456},.state_after=-1};
    if (operation==CLOCK_ABSOLUTE && cancel_state!=PTHREAD_CANCEL_DISABLE) {
        struct timespec now; CHECK(!clock_gettime(CLOCK_MONOTONIC,&now));
        state.request.tv_sec+=now.tv_sec; state.request.tv_nsec=now.tv_nsec;
    }
    pthread_t worker; void *result=NULL;
    CHECK(!pthread_create(&worker,NULL,sleep_worker,&state));
    if (blocked) {
        CHECK(wait_in_syscall(&state.tid,operation==CLOCK_ABSOLUTE ? SYS_clock_nanosleep : SYS_nanosleep));
        CHECK(!pthread_cancel(worker));
    }
    CHECK(!pthread_join(worker,&result) && result==PTHREAD_CANCELED && atomic_load(&state.cleanup));
    int should_return=cancel_state!=PTHREAD_CANCEL_ENABLE || operation==REJECT_CPU_CLOCK;
    CHECK(atomic_load(&state.returned)==should_return);
    if (should_return) {
        int expected_result=0, expected_error=90, expected_state=cancel_state;
        if (operation==REJECT_CPU_CLOCK) expected_result=EINVAL;
        else if (cancel_state==2) {
            expected_state=PTHREAD_CANCEL_DISABLE;
            if (operation==CLOCK_RELATIVE || operation==CLOCK_ABSOLUTE) expected_result=ECANCELED;
            else if (operation==C11_SLEEP) expected_result=-2;
            else {
                expected_result=operation==SECONDS_SLEEP ? state.request.tv_sec : -1;
                expected_error=ECANCELED;
            }
        }
        CHECK(atomic_load(&state.result)==expected_result && atomic_load(&state.error)==expected_error);
        CHECK(atomic_load(&state.state_after)==expected_state);
    }
    if (!blocked) CHECK(state.remaining.tv_sec==123 && state.remaining.tv_nsec==456);
    printf("sleep operation=%d state=%d blocked=%d canceled returned=%d\n",operation,cancel_state,blocked,should_return);
    return 0;
}
enum wait_operation { WAIT_ANY, WAIT_PID, WAIT_ID, RAW_WAIT3, RAW_WAIT4 };
struct child_state {
    enum wait_operation operation;
    int child, cancel_state, blocked, status;
    siginfo_t information;
    struct rusage usage;
    _Atomic int tid, returned, result, error, state_after, cleanup;
};
static void child_cleanup(void *opaque) { struct child_state *s=opaque; atomic_store(&s->cleanup,1); }
static void *wait_worker(void *opaque) {
    struct child_state *s=opaque;
    if (pthread_setcancelstate(s->cancel_state,NULL)) _exit(71);
    pthread_cleanup_push(child_cleanup,s);
    if (!s->blocked && pthread_cancel(pthread_self())) _exit(72);
    errno=90;
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    int options=s->blocked ? 0 : WNOHANG, result;
    switch(s->operation) {
    case WAIT_ANY: result=wait(&s->status); break;
    case WAIT_PID: result=waitpid(s->child,&s->status,options); break;
    case WAIT_ID: result=waitid(P_PID,s->child,&s->information,options|WEXITED); break;
    case RAW_WAIT3: result=wait3(&s->status,options,&s->usage); break;
    case RAW_WAIT4: result=wait4(s->child,&s->status,options,&s->usage); break;
    default: _exit(73);
    }
    atomic_store(&s->result,result); atomic_store(&s->error,errno); atomic_store(&s->returned,1);
    int previous=-1;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous)) _exit(74);
    atomic_store(&s->state_after,previous);
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return (void *)1;
}
static int exercise_wait(enum wait_operation operation, int cancel_state, int blocked) {
    int barrier[2]; CHECK(!pipe(barrier));
    pid_t child=fork(); CHECK(child>=0);
    if (!child) {
        close(barrier[1]); char byte;
        if (read(barrier[0],&byte,1)!=1) _exit(24);
        _exit(23);
    }
    CHECK(!close(barrier[0]));
    struct child_state state={.operation=operation,.child=child,.cancel_state=cancel_state,.blocked=blocked,
        .status=0x12345678,.state_after=-1};
    pthread_t worker; void *result=NULL;
    CHECK(!pthread_create(&worker,NULL,wait_worker,&state));
    int raw=operation>=RAW_WAIT3;
    if (blocked) {
        long number=operation==WAIT_ID ? SYS_waitid : SYS_wait4;
        CHECK(wait_in_syscall(&state.tid,number));
        CHECK(!pthread_cancel(worker));
        if (raw) {
            CHECK(wait_in_syscall(&state.tid,number));
            CHECK(write(barrier[1],"K",1)==1);
        }
    }
    CHECK(!pthread_join(worker,&result) && result==PTHREAD_CANCELED && atomic_load(&state.cleanup));
    int should_return=cancel_state!=PTHREAD_CANCEL_ENABLE || raw;
    CHECK(atomic_load(&state.returned)==should_return);
    if (should_return) {
        int expected_state=(cancel_state==2 && !raw) ? PTHREAD_CANCEL_DISABLE : cancel_state;
        CHECK(atomic_load(&state.state_after)==expected_state);
        if (cancel_state==2 && !raw) CHECK(atomic_load(&state.result)==-1 && atomic_load(&state.error)==ECANCELED);
        else CHECK(atomic_load(&state.result)==(blocked ? child : 0) && atomic_load(&state.error)==90);
    }
    if (raw && blocked) {
        CHECK(WIFEXITED(state.status) && WEXITSTATUS(state.status)==23);
        CHECK(waitpid(child,NULL,WNOHANG)==-1 && errno==ECHILD);
    } else {
        CHECK(write(barrier[1],"K",1)==1);
        int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==23);
    }
    CHECK(!close(barrier[1]));
    printf("child wait=%d state=%d blocked=%d canceled returned=%d reaped=%d\n",operation,cancel_state,blocked,should_return,raw && blocked);
    return 0;
}
int main(void) {
    alarm(30);
    for (int operation=NANO_SLEEP;operation<=REJECT_CPU_CLOCK;operation++)
        for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) CHECK(!exercise_sleep(operation,state,0));
    for (int operation=NANO_SLEEP;operation<REJECT_CPU_CLOCK;operation++) CHECK(!exercise_sleep(operation,PTHREAD_CANCEL_ENABLE,1));
    for (int operation=WAIT_PID;operation<=RAW_WAIT4;operation++)
        for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) CHECK(!exercise_wait(operation,state,0));
    for (int operation=WAIT_ANY;operation<=RAW_WAIT4;operation++) CHECK(!exercise_wait(operation,PTHREAD_CANCEL_ENABLE,1));
    puts("owned-sleep-wait-cancellation-ok");
    return 0;
}
