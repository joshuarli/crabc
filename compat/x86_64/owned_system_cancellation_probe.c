#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <poll.h>
#include <time.h>
#include "owned_cancellation_proc_witness.h"

/* musl 1.2.6 src/process/system.c checks cancellation before the null-command
 * branch and waits through public waitpid. src/stdio/pclose.c instead retries
 * raw __sys_wait4. Neither source installs child-kill/reap cancellation
 * cleanup. The fixture supervisor owns all child cleanup, including failed
 * assertions and deliberately injected tester exit/timeout. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"system-cancel:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
enum operation { SYSTEM_WAIT, PCLOSE_WAIT, SYSTEM_NULL };
struct wait_state {
    enum operation operation;
    int cancel_state, pending;
    char command[128];
    _Atomic int tid, returned, result, error, state_after, cleanup, child_masked, interrupt_ignored;
};
static struct wait_state active;
static pthread_t worker;
static int worker_live, ack[2]={-1,-1}, release_child[2]={-1,-1};
static void interrupt_handler(int signal) { (void)signal; }
static void cleanup_worker(void *opaque) {
    struct wait_state *s=opaque;
    sigset_t mask; struct sigaction action;
    if (pthread_sigmask(SIG_SETMASK,NULL,&mask) || sigaction(SIGINT,NULL,&action)) _exit(91);
    atomic_store(&s->child_masked,sigismember(&mask,SIGCHLD));
    atomic_store(&s->interrupt_ignored,action.sa_handler==SIG_IGN);
    atomic_store(&s->cleanup,1);
}
static void *wait_worker(void *opaque) {
    struct wait_state *s=opaque;
    if (pthread_setcancelstate(s->cancel_state,NULL)) _exit(92);
    FILE *stream=NULL;
    if (s->operation==PCLOSE_WAIT) { stream=popen(s->command,"r"); if (!stream) _exit(93); }
    pthread_cleanup_push(cleanup_worker,s);
    if (s->pending && pthread_cancel(pthread_self())) _exit(94);
    errno=90;
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    int result=s->operation==PCLOSE_WAIT ? pclose(stream) : system(s->operation==SYSTEM_NULL ? NULL : s->command);
    atomic_store(&s->result,result); atomic_store(&s->error,errno); atomic_store(&s->returned,1);
    int previous=-1; if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous)) _exit(95);
    atomic_store(&s->state_after,previous); pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static int wait_in_kernel(void) {
    const struct timespec delay={0,1000000};
    for (int retry=0;retry<2000;retry++) {
        int tid=atomic_load(&active.tid);
        if (tid) {
            char path[96], record[256]; snprintf(path,sizeof path,"/proc/self/task/%d/syscall",tid);
            int fd=owned_cancellation_open_proc(path);
            if (fd>=0) {
                ssize_t count=read(fd,record,sizeof record-1); close(fd);
                if (count>0) { record[count]=0; long number=-1;
                    if (sscanf(record,"%ld",&number)==1 && number==SYS_wait4) return 1; }
            }
        }
        if (atomic_load(&active.cleanup)) return 0;
        nanosleep(&delay,NULL);
    }
    return 0;
}
static int cleanup_observed(void) {
    const struct timespec delay={0,1000000};
    for (int retry=0;retry<2000;retry++) {
        if (atomic_load(&active.cleanup)) return 1;
        nanosleep(&delay,NULL);
    }
    return 0;
}
static int prepare(enum operation operation, int state, int pending) {
    memset(&active,0,sizeof active); active.operation=operation; active.cancel_state=state;
    active.pending=pending; active.state_after=-1;
    CHECK(!pipe(ack) && !pipe(release_child));
    CHECK(snprintf(active.command,sizeof active.command,"crabc-system-wait %d %d %d %d 23",
        ack[0],ack[1],release_child[0],release_child[1])>0);
    struct sigaction action={.sa_handler=interrupt_handler}; sigemptyset(&action.sa_mask);
    CHECK(!sigaction(SIGINT,&action,NULL));
    CHECK(!pthread_create(&worker,NULL,wait_worker,&active)); worker_live=1; return 0;
}
static int child_pid(void) {
    struct pollfd observed={.fd=ack[0],.events=POLLIN};
    if (poll(&observed,1,2000)!=1) return -1;
    int pid=-1; return read(ack[0],&pid,sizeof pid)==sizeof pid ? pid : -1;
}
static int release_target(void) { CHECK(write(release_child[1],"K",1)==1); return 0; }
static int join_worker(int canceled) {
    void *result=(void *)1; int error=pthread_join(worker,&result);
    if (!error) worker_live=0;
    CHECK(!error && result==(canceled ? PTHREAD_CANCELED : NULL)); return 0;
}
static int check_child_live(int pid) {
    int status; CHECK(waitpid(pid,&status,WNOHANG)==0); return 0;
}
static int reap_target(int pid) {
    int status; CHECK(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==23); return 0;
}
/* Fixture cleanup runs after every case result. Releasing first lets disabled
 * and deliberately raw pclose waits finish before their worker is joined. */
static int finish_case(void) {
    if (release_child[1]>=0) (void)write(release_child[1],"K",1);
    if (worker_live) {
        void *result; if (pthread_join(worker,&result)) return 1;
        worker_live=0;
    }
    for (int index=0;index<2;index++) {
        if (ack[index]>=0) { close(ack[index]); ack[index]=-1; }
        if (release_child[index]>=0) { close(release_child[index]); release_child[index]=-1; }
    }
    int status, pid;
    do { pid=waitpid(-1,&status,0); } while (pid>0 || (pid<0 && errno==EINTR));
    return pid==-1 && errno==ECHILD ? 0 : 1;
}
static int null_command(int state) {
    CHECK(!prepare(SYSTEM_NULL,state,1) && cleanup_observed() && !join_worker(1));
    CHECK(atomic_load(&active.returned)==(state!=PTHREAD_CANCEL_ENABLE));
    if (state!=PTHREAD_CANCEL_ENABLE) CHECK(atomic_load(&active.result)==1 &&
        atomic_load(&active.error)==90 && atomic_load(&active.state_after)==state);
    CHECK(!atomic_load(&active.child_masked) && !atomic_load(&active.interrupt_ignored));
    int status; CHECK(waitpid(-1,&status,WNOHANG)==-1 && errno==ECHILD);
    printf("system null pending state=%d\n",state); return 0;
}
static int message_wait(enum operation operation, int state, int pending, int ordinary_signal) {
    CHECK(!prepare(operation,state,pending));
    if (operation==SYSTEM_WAIT && pending && state==PTHREAD_CANCEL_ENABLE) {
        CHECK(cleanup_observed() && !join_worker(1) && !atomic_load(&active.returned));
        CHECK(!atomic_load(&active.child_masked) && !atomic_load(&active.interrupt_ignored));
        int status; CHECK(waitpid(-1,&status,WNOHANG)==-1 && errno==ECHILD);
    } else {
        int pid=child_pid(); CHECK(pid>0);
        int canceled_wait=operation==SYSTEM_WAIT && state!=PTHREAD_CANCEL_DISABLE && !ordinary_signal;
        if (!pending || operation==PCLOSE_WAIT || state==PTHREAD_CANCEL_DISABLE) CHECK(wait_in_kernel());
        if (!pending) {
            if (ordinary_signal) CHECK(!syscall(SYS_tgkill,getpid(),atomic_load(&active.tid),SIGUSR1));
            else CHECK(!pthread_cancel(worker));
        }
        if (canceled_wait) {
            CHECK(cleanup_observed() && !join_worker(1));
            CHECK(!check_child_live(pid));
            CHECK(atomic_load(&active.returned)==(state==2));
            if (state==2) CHECK(atomic_load(&active.result)==-1 && atomic_load(&active.error)==ECANCELED &&
                atomic_load(&active.state_after)==PTHREAD_CANCEL_DISABLE);
            CHECK(atomic_load(&active.child_masked)==(state==PTHREAD_CANCEL_ENABLE));
            CHECK(atomic_load(&active.interrupt_ignored)==(state==PTHREAD_CANCEL_ENABLE));
            CHECK(!release_target() && !reap_target(pid));
        } else {
            CHECK(wait_in_kernel() && !atomic_load(&active.returned) && !check_child_live(pid));
            CHECK(!release_target() && cleanup_observed() && !join_worker(!ordinary_signal));
            CHECK(atomic_load(&active.returned) && atomic_load(&active.result)==(23<<8));
            CHECK(atomic_load(&active.error)==(ordinary_signal && operation==SYSTEM_WAIT ? EINTR : 90));
            CHECK(atomic_load(&active.state_after)==state);
            CHECK(!atomic_load(&active.child_masked) && !atomic_load(&active.interrupt_ignored));
            int status; CHECK(waitpid(pid,&status,WNOHANG)==-1 && errno==ECHILD);
        }
    }
    printf("system wait operation=%d state=%d pending=%d ordinary-signal=%d\n",operation,state,pending,ordinary_signal);
    return 0;
}
static int run_tests(const char *injection) {
    alarm(25);
    struct sigaction action={.sa_handler=SIG_IGN}; sigemptyset(&action.sa_mask);
    CHECK(!sigaction(SIGQUIT,&action,NULL) && !sigaction(SIGPIPE,&action,NULL));
    action.sa_handler=interrupt_handler; CHECK(!sigaction(SIGUSR1,&action,NULL));
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask,SIGUSR2);
    CHECK(!pthread_sigmask(SIG_BLOCK,&mask,NULL));
    CHECK(!setenv("CRABC_SYSTEM_CANCELLATION","source-owned-child",1));
    if (injection) {
        CHECK(!prepare(SYSTEM_WAIT,PTHREAD_CANCEL_ENABLE,0) && child_pid()>0 && wait_in_kernel());
        if (!strcmp(injection,"failure")) _exit(44);
        alarm(1); for (;;) pause();
    }
    int result=message_wait(SYSTEM_WAIT,PTHREAD_CANCEL_ENABLE,0,0);
    int cleaned=finish_case(); CHECK(!result && !cleaned);
    for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) {
        result=null_command(state); cleaned=finish_case(); CHECK(!result && !cleaned);
        for (int operation=SYSTEM_WAIT;operation<=PCLOSE_WAIT;operation++) {
            for (int pending=0;pending<=1;pending++) {
                result=message_wait(operation,state,pending,0); cleaned=finish_case(); CHECK(!result && !cleaned);
            }
        }
    }
    for (int operation=SYSTEM_WAIT;operation<=PCLOSE_WAIT;operation++) {
        result=message_wait(operation,PTHREAD_CANCEL_ENABLE,0,1); cleaned=finish_case(); CHECK(!result && !cleaned);
    }
    puts("owned-system-cancellation-ok"); return 0;
}
int main(int argc, char **argv) {
    CHECK(argc==1 || (argc==2 && (!strcmp(argv[1],"failure") || !strcmp(argv[1],"timeout"))));
    /* Test-only Linux child ownership: adopt descendants after an injected
     * tester failure, kill only its dedicated process group, and reap all. */
    CHECK(!syscall(SYS_prctl,36,1,0,0,0)); /* PR_SET_CHILD_SUBREAPER */
    pid_t tester=fork(); CHECK(tester>=0);
    if (!tester) {
        if (setpgid(0,0)) _exit(96);
        int result=run_tests(argc==2 ? argv[1] : NULL); if (fflush(stdout)) result=1; _exit(result);
    }
    /* Leave the tester waitable until group cleanup so its numeric process
     * group identity cannot be reused by an unrelated child. */
    siginfo_t observed; int observed_result;
    do { observed_result=waitid(P_PID,tester,&observed,WEXITED|WNOWAIT); } while (observed_result<0 && errno==EINTR);
    int killed=kill(-tester,SIGKILL); CHECK(!killed || errno==ESRCH);
    int status, waited;
    do { waited=waitpid(tester,&status,0); } while (waited<0 && errno==EINTR);
    int reaped=0, child_status, child;
    do { child=waitpid(-1,&child_status,0); if (child>0) reaped++; } while (child>0 || (child<0 && errno==EINTR));
    CHECK(!observed_result && observed.si_pid==tester && waited==tester && child<0 && errno==ECHILD);
    if (argc==2) {
        CHECK(reaped>=1 && (!strcmp(argv[1],"failure") ? WIFEXITED(status) && WEXITSTATUS(status)==44 :
            WIFSIGNALED(status) && WTERMSIG(status)==SIGALRM));
        printf("system supervisor %s: child group removed and reaped\n",argv[1]);
    } else CHECK(WIFEXITED(status) && WEXITSTATUS(status)==0 && reaped==0);
    return 0;
}
