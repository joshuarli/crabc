#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include "owned_cancellation_proc_witness.h"

/* musl 1.2.6 src/ipc/{msgsnd,msgrcv}.c put the direct Linux syscalls
 * inside syscall_cp, without queue removal or message rollback cleanup.
 * A supervisor owns this fixture's IPC_PRIVATE queue and removes it after
 * every child outcome, including assertion failure, _exit, and timeout. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"sysv-message-cancel:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
struct message { long type; unsigned char text[4]; };
enum operation { SEND, RECEIVE };
struct message_state {
    enum operation operation;
    int queue, cancel_state, pending, flags;
    struct message message;
    _Atomic int tid, returned, result, error, state_after, cleanup;
};
static const struct message old_message={3,{'o','l','d','!'}};
static const struct message new_message={7,{'n','e','w','!'}};
static void cleanup_waiter(void *opaque) {
    struct message_state *s=opaque; atomic_store(&s->cleanup,1);
}
static void *message_worker(void *opaque) {
    struct message_state *s=opaque;
    if (pthread_setcancelstate(s->cancel_state,NULL)) _exit(81);
    pthread_cleanup_push(cleanup_waiter,s);
    if (s->pending && pthread_cancel(pthread_self())) _exit(82);
    errno=90;
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    int result=s->operation==SEND ? msgsnd(s->queue,&s->message,4,s->flags) :
        (int)msgrcv(s->queue,&s->message,4,0,s->flags);
    atomic_store(&s->result,result); atomic_store(&s->error,errno); atomic_store(&s->returned,1);
    int previous=-1; if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous)) _exit(83);
    atomic_store(&s->state_after,previous); pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static void initialize(struct message_state *s, int q, enum operation operation, int state, int pending) {
    memset(s,0,sizeof *s); s->queue=q; s->operation=operation; s->cancel_state=state;
    s->pending=pending; s->state_after=-1;
    memset(&s->message,0x5a,sizeof s->message);
    if (operation==SEND) s->message=new_message;
}
static int in_message_wait(struct message_state *s) {
    const struct timespec delay={0,1000000};
    for (int retry=0;retry<2000;retry++) {
        int tid=atomic_load(&s->tid);
        if (tid) {
            char path[96], line[256]; snprintf(path,sizeof path,"/proc/self/task/%d/syscall",tid);
            int fd=owned_cancellation_open_proc(path);
            if (fd>=0) {
                ssize_t count=read(fd,line,sizeof line-1); close(fd);
                if (count>0) {
                    line[count]=0; long number=-1;
                    if (sscanf(line,"%ld",&number)==1 && number==(s->operation==SEND ? SYS_msgsnd : SYS_msgrcv)) return 1;
                }
            }
        }
        if (atomic_load(&s->returned)) return 0;
        nanosleep(&delay,NULL);
    }
    return 0;
}
static int same_message(const struct message *a, const struct message *b) {
    return a->type==b->type && !memcmp(a->text,b->text,4);
}
static int queue_contents(int queue, const struct message *expected) {
    struct msqid_ds status; CHECK(!msgctl(queue,IPC_STAT,&status));
    CHECK(status.msg_qnum==(unsigned long)(expected!=NULL) && status.msg_cbytes==(expected ? 4ul : 0ul));
    struct message received;
    if (expected) CHECK(msgrcv(queue,&received,4,0,IPC_NOWAIT)==4 && same_message(&received,expected));
    CHECK(msgrcv(queue,&received,4,0,IPC_NOWAIT)==-1 && errno==ENOMSG);
    return 0;
}
static int worker_output(struct message_state *s, int success) {
    if (s->operation==SEND) CHECK(same_message(&s->message,&new_message));
    else if (success) CHECK(same_message(&s->message,&old_message));
    else {
        struct message untouched; memset(&untouched,0x5a,sizeof untouched);
        CHECK(!memcmp(&s->message,&untouched,sizeof untouched));
    }
    CHECK(atomic_load(&s->cleanup)); return 0;
}
/* scenario: ready operation, NOWAIT refusal, or invalid queue id. */
static int pending_message(int queue, enum operation operation, int state, int scenario) {
    struct message_state s; initialize(&s,scenario==2 ? -1 : queue,operation,state,1); s.flags=IPC_NOWAIT;
    int seeded=scenario==0 ? operation==RECEIVE : scenario==1 && operation==SEND;
    if (seeded) CHECK(!msgsnd(queue,&old_message,4,IPC_NOWAIT));
    pthread_t thread; void *result=NULL; CHECK(!pthread_create(&thread,NULL,message_worker,&s));
    CHECK(!pthread_join(thread,&result) && result==PTHREAD_CANCELED);
    int success=state==PTHREAD_CANCEL_DISABLE && scenario==0;
    CHECK(atomic_load(&s.returned)==(state!=PTHREAD_CANCEL_ENABLE) && !worker_output(&s,success));
    if (state!=PTHREAD_CANCEL_ENABLE) {
        int error=state==2 ? ECANCELED : scenario==2 ? EINVAL : scenario==1 ? operation==SEND ? EAGAIN : ENOMSG : 90;
        CHECK(atomic_load(&s.error)==error && atomic_load(&s.result)==(success ? operation==SEND ? 0 : 4 : -1));
        CHECK(atomic_load(&s.state_after)==PTHREAD_CANCEL_DISABLE);
    }
    const struct message *left=seeded ? &old_message : NULL;
    if (success) left=operation==SEND ? &new_message : NULL;
    CHECK(!queue_contents(queue,left));
    printf("sysv pending operation=%d state=%d scenario=%d changed=%d\n",operation,state,scenario,success);
    return 0;
}
static int blocked_message(int queue, enum operation operation, int state) {
    struct message_state s; initialize(&s,queue,operation,state,0);
    if (operation==SEND) CHECK(!msgsnd(queue,&old_message,4,IPC_NOWAIT));
    pthread_t thread; void *result=NULL; CHECK(!pthread_create(&thread,NULL,message_worker,&s));
    CHECK(in_message_wait(&s) && !pthread_cancel(thread));
    /* Linux message syscalls never restart after a caught signal, including
     * musl's internal cancellation signal while cancellation is disabled. */
    CHECK(!pthread_join(thread,&result) && result==PTHREAD_CANCELED && !worker_output(&s,0));
    CHECK(atomic_load(&s.returned)==(state!=PTHREAD_CANCEL_ENABLE));
    if (state!=PTHREAD_CANCEL_ENABLE) {
        CHECK(atomic_load(&s.result)==-1);
        CHECK(atomic_load(&s.error)==(state==PTHREAD_CANCEL_DISABLE ? EINTR : ECANCELED) && atomic_load(&s.state_after)==PTHREAD_CANCEL_DISABLE);
    }
    CHECK(!queue_contents(queue,operation==SEND ? &old_message : NULL));
    printf("sysv blocked operation=%d state=%d changed=0\n",operation,state); return 0;
}
static void interrupt_handler(int signal) { (void)signal; }
static int interrupted_message(int queue, enum operation operation, int restart) {
    struct sigaction action={.sa_handler=interrupt_handler,.sa_flags=restart ? SA_RESTART : 0};
    sigemptyset(&action.sa_mask); CHECK(!sigaction(SIGUSR1,&action,NULL));
    struct message_state s; initialize(&s,queue,operation,PTHREAD_CANCEL_ENABLE,0);
    if (operation==SEND) CHECK(!msgsnd(queue,&old_message,4,IPC_NOWAIT));
    pthread_t thread; void *result=(void *)1; CHECK(!pthread_create(&thread,NULL,message_worker,&s));
    CHECK(in_message_wait(&s) && !syscall(SYS_tgkill,getpid(),atomic_load(&s.tid),SIGUSR1));
    CHECK(!pthread_join(thread,&result) && result==NULL && !worker_output(&s,0));
    CHECK(atomic_load(&s.returned) && atomic_load(&s.result)==-1 && atomic_load(&s.error)==EINTR);
    CHECK(atomic_load(&s.state_after)==PTHREAD_CANCEL_ENABLE);
    CHECK(!queue_contents(queue,operation==SEND ? &old_message : NULL));
    printf("sysv interrupted operation=%d restart=%d errno=EINTR\n",operation,restart); return 0;
}
static int child_tests(int queue) {
    alarm(30);
    struct msqid_ds status; CHECK(!msgctl(queue,IPC_STAT,&status)); status.msg_qbytes=4;
    CHECK(!msgctl(queue,IPC_SET,&status));
    for (int operation=SEND;operation<=RECEIVE;operation++) {
        for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) {
            for (int scenario=0;scenario<3;scenario++) CHECK(!pending_message(queue,operation,state,scenario));
            CHECK(!blocked_message(queue,operation,state));
        }
        CHECK(!interrupted_message(queue,operation,0) && !interrupted_message(queue,operation,1));
    }
    puts("owned-sysv-message-cancellation-ok"); return 0;
}
int main(void) {
    int queue=msgget(IPC_PRIVATE,0600); CHECK(queue>=0);
    pid_t child=fork();
    if (!child) { int result=child_tests(queue); if (fflush(stdout)) result=1; _exit(result); }
    int status=0, waited=-1;
    if (child>0) do { waited=waitpid(child,&status,0); } while (waited==-1 && errno==EINTR);
    int removed=msgctl(queue,IPC_RMID,NULL);
    CHECK(child>0 && waited==child && removed==0 && WIFEXITED(status) && WEXITSTATUS(status)==0);
    return 0;
}
