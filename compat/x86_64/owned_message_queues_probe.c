#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mqueue.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "owned_cancellation_proc_witness.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"message-queues:%d: %s errno=%d\n",__LINE__,#x,errno); _Exit(95); } } while(0)
_Static_assert(sizeof(mqd_t)==4 && (mqd_t)-1<0,"mqd_t ABI");
_Static_assert(sizeof(struct mq_attr)==64 && _Alignof(struct mq_attr)==8,"mq_attr ABI");
_Static_assert(offsetof(struct mq_attr,mq_flags)==0 && offsetof(struct mq_attr,mq_maxmsg)==8 && offsetof(struct mq_attr,mq_msgsize)==16 && offsetof(struct mq_attr,mq_curmsgs)==24,"mq_attr fields");
_Static_assert(sizeof(struct sigevent)==64 && offsetof(struct sigevent,sigev_notify)==12 && offsetof(struct sigevent,sigev_notify_function)==16 && offsetof(struct sigevent,sigev_notify_attributes)==24,"sigevent ABI");
static char queue_name[64];
static mqd_t create_queue(void) {
    static int sequence;
    snprintf(queue_name,sizeof queue_name,"/owned-mq-%d-%d",getpid(),sequence++);
    struct mq_attr attributes={.mq_maxmsg=2,.mq_msgsize=32};
    mqd_t queue=mq_open(queue_name,O_CREAT|O_EXCL|O_RDWR,0600,&attributes);
    CHECK(queue>=0); return queue;
}
static void destroy_queue(mqd_t queue) { CHECK(mq_unlink(queue_name)==0 && mq_close(queue)==0); }
static struct timespec deadline_after(int seconds) { struct timespec value; CHECK(clock_gettime(CLOCK_REALTIME,&value)==0); value.tv_sec+=seconds; return value; }
static void pause_briefly(void) { const struct timespec delay={0,1000000}; CHECK(nanosleep(&delay,NULL)==0); }
static void child_ok(pid_t child) { int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0); }
/* A read-only proc fd survives each private chroot. Count actual live tasks
 * and descriptors to prove notification worker/socket retirement. */
static int proc_entries(const char *path) {
    int fd=owned_cancellation_open_proc(path); CHECK(fd>=0); int count=0;
    struct entry { uint64_t inode; int64_t offset; unsigned short length; unsigned char type; char name[]; };
    _Alignas(8) char buffer[4096]; long bytes;
    while((bytes=syscall(SYS_getdents64,fd,buffer,sizeof buffer))>0) {
        for(long position=0;position<bytes;) {
            struct entry *entry=(void *)(buffer+position);
            CHECK(entry->length>=20 && position+entry->length<=bytes);
            if(strcmp(entry->name,".") && strcmp(entry->name,"..")) count++;
            position+=entry->length;
        }
    }
    CHECK(bytes==0 && close(fd)==0); return count;
}
static void wait_retirement(int tasks,int descriptors) {
    for(int i=0;i<3000;i++) {
        if(proc_entries("/proc/self/task")==tasks && proc_entries("/proc/self/fd")==descriptors) return;
        pause_briefly();
    }
    CHECK(0);
}
static void names_attributes_transfer(void) {
    errno=0; CHECK(mq_open("",O_RDONLY)==-1 && errno==ENOENT);
    errno=0; CHECK(mq_open("/",O_RDONLY)==-1 && errno==ENOENT);
    errno=0; CHECK(mq_open("//bad",O_RDONLY)==-1 && errno==EACCES);
    errno=0; CHECK(mq_open("/bad/name",O_RDONLY)==-1 && errno==EACCES);
    errno=0; CHECK(mq_unlink("//bad")==-1 && errno==EACCES);
    char long_name[257]; memset(long_name,'n',256); long_name[256]=0;
    errno=0; CHECK(mq_open(long_name,O_RDONLY)==-1 && errno==ENAMETOOLONG);
    long_name[255]=0;
    struct mq_attr attributes={.mq_maxmsg=2,.mq_msgsize=32};
    mqd_t maximum=mq_open(long_name,O_CREAT|O_EXCL|O_RDWR,0600,&attributes);
    CHECK(maximum>=0 && mq_unlink(long_name)==0 && mq_close(maximum)==0);
    mode_t previous=umask(0027);
    snprintf(queue_name,sizeof queue_name,"/owned-mq-%d-mode",getpid());
    errno=71; mqd_t queue=mq_open(queue_name,O_CREAT|O_EXCL|O_RDWR,0777,&attributes);
    CHECK(queue>=0 && errno==71); umask(previous);
    struct stat status; CHECK(fstat(queue,&status)==0 && (status.st_mode&0777)==0750);
    /* Linux creates message queue descriptors with FD_CLOEXEC even when the
     * source passes no explicit O_CLOEXEC flag. */
    CHECK(fcntl(queue,F_GETFD)==FD_CLOEXEC);
    mqd_t second=mq_open(queue_name+1,O_RDWR); CHECK(second>=0);
    errno=0; CHECK(mq_open(queue_name,O_CREAT|O_EXCL|O_RDWR,0600,&attributes)==-1 && errno==EEXIST);
    CHECK(mq_close(second)==0);
    memset(&attributes,0xcc,sizeof attributes); errno=71;
    CHECK(mq_getattr(queue,&attributes)==0 && errno==71);
    CHECK(attributes.mq_flags==0 && attributes.mq_maxmsg==2 && attributes.mq_msgsize==32 && attributes.mq_curmsgs==0);
    struct mq_attr changed={.mq_flags=O_NONBLOCK},old;
    CHECK(mq_setattr(queue,&changed,&old)==0 && old.mq_flags==0);
    char buffer[32]; unsigned priority=777;
    errno=0; CHECK(mq_receive(queue,buffer,sizeof buffer,&priority)==-1 && errno==EAGAIN && priority==777);
    errno=71; CHECK(mq_send(queue,"low",3,1)==0 && errno==71);
    CHECK(mq_send(queue,"high",4,32767)==0);
    errno=0; CHECK(mq_send(queue,"full",4,0)==-1 && errno==EAGAIN);
    errno=0; CHECK(mq_send(queue,"large",33,0)==-1 && errno==EMSGSIZE);
    errno=0; CHECK(mq_send(queue,"priority",8,32768)==-1 && errno==EINVAL);
    errno=0; CHECK(mq_receive(queue,buffer,31,&priority)==-1 && errno==EMSGSIZE);
    CHECK(mq_getattr(queue,&attributes)==0 && attributes.mq_curmsgs==2);
    CHECK(mq_receive(queue,buffer,sizeof buffer,&priority)==4 && priority==32767 && !memcmp(buffer,"high",4));
    CHECK(mq_receive(queue,buffer,sizeof buffer,NULL)==3 && !memcmp(buffer,"low",3));
    CHECK(mq_send(queue,"first",5,6)==0 && mq_send(queue,"second",6,6)==0);
    CHECK(mq_receive(queue,buffer,sizeof buffer,&priority)==5 && priority==6 && !memcmp(buffer,"first",5));
    CHECK(mq_receive(queue,buffer,sizeof buffer,&priority)==6 && !memcmp(buffer,"second",6));
    changed.mq_flags=0; CHECK(mq_setattr(queue,&changed,&old)==0 && old.mq_flags==O_NONBLOCK);
    const struct timespec expired={0,0},large_time={0x200000000LL,0},invalid={0,1000000000};
    errno=0; CHECK(mq_timedreceive(queue,buffer,sizeof buffer,&priority,&expired)==-1 && errno==ETIMEDOUT);
    errno=0; CHECK(mq_timedreceive(queue,buffer,sizeof buffer,&priority,&invalid)==-1 && errno==EINVAL);
    CHECK(mq_timedsend(queue,"a",1,4,&large_time)==0 && mq_timedsend(queue,"b",1,4,&expired)==0);
    errno=0; CHECK(mq_timedsend(queue,"full",4,4,&expired)==-1 && errno==ETIMEDOUT);
    errno=0; CHECK(mq_timedsend(queue,"full",4,4,&invalid)==-1 && errno==EINVAL);
    CHECK(mq_timedreceive(queue,buffer,sizeof buffer,NULL,&expired)==1 && buffer[0]=='a');
    CHECK(mq_timedreceive(queue,buffer,sizeof buffer,NULL,&large_time)==1 && buffer[0]=='b');
    CHECK(mq_send(queue,"",0,0)==0 && mq_receive(queue,buffer,sizeof buffer,NULL)==0);
    CHECK(mq_unlink(queue_name)==0);
    errno=0; CHECK(mq_open(queue_name,O_RDONLY)==-1 && errno==ENOENT);
    CHECK(mq_send(queue,"live",4,0)==0 && mq_receive(queue,buffer,sizeof buffer,NULL)==4);
    attributes=(struct mq_attr){.mq_maxmsg=1,.mq_msgsize=8};
    mqd_t replacement=mq_open(queue_name,O_CREAT|O_EXCL|O_RDWR,0600,&attributes); CHECK(replacement>=0);
    CHECK(mq_getattr(replacement,&attributes)==0 && attributes.mq_maxmsg==1 && attributes.mq_msgsize==8 && attributes.mq_curmsgs==0);
    CHECK(mq_unlink(queue_name)==0 && mq_close(replacement)==0 && mq_close(queue)==0);
    errno=0; CHECK(mq_close(queue)==-1 && errno==EBADF);
    errno=0; CHECK(mq_getattr(-1,&attributes)==-1 && errno==EBADF);
}
struct waiter { mqd_t queue; int send,timed; _Atomic int tid,cleaned; int result,error; };
static void waiter_cleanup(void *argument) { struct waiter *waiter=argument; atomic_store(&waiter->cleaned,1); }
static void *transfer_wait(void *argument) {
    struct waiter *waiter=argument; char buffer[32]; struct timespec deadline=deadline_after(20);
    pthread_cleanup_push(waiter_cleanup,waiter);
    atomic_store(&waiter->tid,(int)syscall(SYS_gettid)); errno=71;
    if(waiter->send) waiter->result=waiter->timed ? mq_timedsend(waiter->queue,"worker",6,3,&deadline) : mq_send(waiter->queue,"worker",6,3);
    else waiter->result=waiter->timed ? (int)mq_timedreceive(waiter->queue,buffer,sizeof buffer,NULL,&deadline) : (int)mq_receive(waiter->queue,buffer,sizeof buffer,NULL);
    waiter->error=errno;
    pthread_cleanup_pop(1);
    return (void *)12;
}
static void wait_transfer_blocked(struct waiter *waiter) {
    for(int i=0;i<3000;i++) {
        int tid=atomic_load(&waiter->tid);
        if(tid) {
            char path[96],line[256]; snprintf(path,sizeof path,"/proc/self/task/%d/syscall",tid);
            int fd=owned_cancellation_open_proc(path);
            if(fd>=0) { ssize_t n=read(fd,line,sizeof line-1); CHECK(close(fd)==0);
                if(n>0) { line[n]=0; long number=-1; unsigned long descriptor=0;
                    if(sscanf(line,"%ld %lx",&number,&descriptor)==2 && number==(waiter->send ? SYS_mq_timedsend : SYS_mq_timedreceive) && descriptor==(unsigned)waiter->queue) return;
                }
            }
        }
        pause_briefly();
    }
    CHECK(0);
}
static volatile sig_atomic_t handled;
static void signal_handler(int signal) { CHECK(signal==SIGUSR1); handled=1; }
static void blocking_transfer(int send,int timed,int completion) {
    mqd_t queue=create_queue();
    if(send) CHECK(mq_send(queue,"a",1,1)==0 && mq_send(queue,"b",1,1)==0);
    struct waiter waiter={.queue=queue,.send=send,.timed=timed}; pthread_t thread;
    struct sigaction action={.sa_handler=signal_handler,.sa_flags=completion==2 ? SA_RESTART : 0},old;
    CHECK(sigemptyset(&action.sa_mask)==0 && sigaction(SIGUSR1,&action,&old)==0); handled=0;
    CHECK(pthread_create(&thread,NULL,transfer_wait,&waiter)==0); wait_transfer_blocked(&waiter);
    if(completion==0) CHECK(pthread_cancel(thread)==0);
    else {
        CHECK(pthread_kill(thread,SIGUSR1)==0);
        for(int i=0;i<3000 && !handled;i++) pause_briefly(); CHECK(handled);
        if(completion==2) {
            wait_transfer_blocked(&waiter);
            char buffer[32];
            if(send) CHECK(mq_receive(queue,buffer,sizeof buffer,NULL)==1);
            else CHECK(mq_send(queue,"released",8,0)==0);
        }
    }
    void *result; CHECK(pthread_join(thread,&result)==0 && atomic_load(&waiter.cleaned));
    if(completion==0) CHECK(result==PTHREAD_CANCELED);
    else if(completion==1) CHECK(result==(void *)12 && waiter.result==-1 && waiter.error==EINTR);
    else CHECK(result==(void *)12 && waiter.result==(send ? 0 : 8) && waiter.error==71);
    CHECK(sigaction(SIGUSR1,&old,NULL)==0);
    struct mq_attr attributes; CHECK(mq_getattr(queue,&attributes)==0 && attributes.mq_curmsgs==(send ? 2 : 0));
    destroy_queue(queue);
}
static void signal_notifications(void) {
    mqd_t queue=create_queue();
    sigset_t set,previous; CHECK(sigemptyset(&set)==0 && sigaddset(&set,SIGUSR2)==0 && pthread_sigmask(SIG_BLOCK,&set,&previous)==0);
    struct sigevent event={.sigev_notify=SIGEV_SIGNAL,.sigev_signo=SIGUSR2,.sigev_value.sival_int=471};
    CHECK(mq_notify(queue,&event)==0);
    errno=0; CHECK(mq_notify(queue,&event)==-1 && errno==EBUSY);
    pid_t child=fork(); CHECK(child>=0);
    if(!child) { CHECK(mq_close(queue)==0); _Exit(0); }
    child_ok(child); /* Child close must not withdraw the parent registration. */
    CHECK(mq_send(queue,"signal",6,0)==0);
    siginfo_t info; const struct timespec timeout={3,0},zero={0,0};
    CHECK(sigtimedwait(&set,&info,&timeout)==SIGUSR2 && info.si_code==SI_MESGQ && info.si_value.sival_int==471 && info.si_pid==getpid());
    char buffer[32]; CHECK(mq_receive(queue,buffer,sizeof buffer,NULL)==6);
    CHECK(mq_send(queue,"once",4,0)==0);
    errno=0; CHECK(sigtimedwait(&set,&info,&zero)==-1 && errno==EAGAIN);
    CHECK(mq_receive(queue,buffer,sizeof buffer,NULL)==4);
    event.sigev_notify=SIGEV_NONE; CHECK(mq_notify(queue,&event)==0);
    errno=0; CHECK(mq_notify(queue,&event)==-1 && errno==EBUSY);
    CHECK(mq_notify(queue,NULL)==0 && mq_notify(queue,&event)==0);
    CHECK(mq_send(queue,"none",4,0)==0 && mq_receive(queue,buffer,sizeof buffer,NULL)==4);
    CHECK(mq_notify(queue,&event)==0 && mq_notify(queue,NULL)==0);
    CHECK(pthread_sigmask(SIG_SETMASK,&previous,NULL)==0); destroy_queue(queue);
}
struct callback_state { sem_t completed; _Atomic int calls; mqd_t queue; int rearm; };
static void thread_callback(union sigval value) {
    struct callback_state *state=value.sival_ptr;
    sigset_t mask; CHECK(pthread_sigmask(SIG_SETMASK,NULL,&mask)==0 && sigismember(&mask,SIGUSR1)==1 && sigismember(&mask,SIGUSR2)==1);
    pthread_attr_t attributes; int detached;
    CHECK(pthread_getattr_np(pthread_self(),&attributes)==0 && pthread_attr_getdetachstate(&attributes,&detached)==0 && detached==PTHREAD_CREATE_DETACHED);
    CHECK(pthread_attr_destroy(&attributes)==0);
    int call=atomic_fetch_add(&state->calls,1)+1;
    char buffer[32]; CHECK(mq_receive(state->queue,buffer,sizeof buffer,NULL)==1);
    if(state->rearm && call<4) {
        struct sigevent again={.sigev_notify=SIGEV_THREAD,.sigev_notify_function=thread_callback,.sigev_value.sival_ptr=state};
        CHECK(mq_notify(state->queue,&again)==0 && mq_send(state->queue,"n",1,0)==0);
    } else CHECK(sem_post(&state->completed)==0);
}
static void unexpected_callback(union sigval value) { (void)value; CHECK(0); }
static void thread_notifications(void) {
    mqd_t queue=create_queue();
    struct callback_state state={.queue=queue}; CHECK(sem_init(&state.completed,0,0)==0);
    pthread_attr_t attributes; CHECK(pthread_attr_init(&attributes)==0 && pthread_attr_setdetachstate(&attributes,PTHREAD_CREATE_DETACHED)==0 && pthread_attr_setstacksize(&attributes,262144)==0);
    struct sigevent event={.sigev_notify=SIGEV_THREAD,.sigev_notify_function=thread_callback,.sigev_value.sival_ptr=&state,.sigev_notify_attributes=&attributes};
    int tasks=proc_entries("/proc/self/task"),descriptors=proc_entries("/proc/self/fd");
    CHECK(mq_notify(queue,&event)==0);
    for(int i=0;i<8;i++) { errno=0; CHECK(mq_notify(queue,&event)==-1 && errno==EBUSY); }
    struct sigevent copied_event=event; event.sigev_notify_function=unexpected_callback; event.sigev_value.sival_ptr=NULL;
    CHECK(mq_send(queue,"n",1,0)==0); struct timespec deadline=deadline_after(3);
    CHECK(sem_timedwait(&state.completed,&deadline)==0 && atomic_load(&state.calls)==1);
    wait_retirement(tasks,descriptors); event=copied_event;
    CHECK(mq_notify(queue,&event)==0 && mq_notify(queue,NULL)==0); wait_retirement(tasks,descriptors);
    CHECK(atomic_load(&state.calls)==1);
    CHECK(mq_notify(queue,&event)==0 && mq_close(queue)==0);
    wait_retirement(tasks,descriptors-1); CHECK(atomic_load(&state.calls)==1);
    queue=mq_open(queue_name,O_RDWR); CHECK(queue>=0); state.queue=queue;
    for(int i=0;i<8;i++) { errno=0; CHECK(mq_notify(-1,&event)==-1 && errno==EBADF); }
    wait_retirement(tasks,descriptors);
    atomic_store(&state.calls,0); state.rearm=1; event.sigev_notify_attributes=NULL;
    CHECK(mq_notify(queue,&event)==0 && mq_send(queue,"n",1,0)==0); deadline=deadline_after(3);
    CHECK(sem_timedwait(&state.completed,&deadline)==0 && atomic_load(&state.calls)==4);
    wait_retirement(tasks,descriptors);
    CHECK(pthread_attr_destroy(&attributes)==0 && sem_destroy(&state.completed)==0); destroy_queue(queue);
}
static int pending_completed;
static void *pending_cancel(void *unused) {
    (void)unused; CHECK(pthread_cancel(pthread_self())==0);
    mqd_t queue=create_queue(); struct mq_attr attributes;
    CHECK(mq_getattr(queue,&attributes)==0 && mq_setattr(queue,&attributes,NULL)==0);
    struct callback_state state={.queue=queue}; CHECK(sem_init(&state.completed,0,0)==0);
    struct sigevent event={.sigev_notify=SIGEV_THREAD,.sigev_notify_function=thread_callback,.sigev_value.sival_ptr=&state};
    CHECK(mq_notify(queue,&event)==0 && mq_notify(queue,NULL)==0);
    CHECK(mq_unlink(queue_name)==0 && mq_close(queue)==0);
    pending_completed=1; pthread_testcancel(); CHECK(0); return NULL;
}
static void creation_failure_cleanup(void) {
    pid_t child=fork(); CHECK(child>=0);
    if(!child) {
        int tasks=proc_entries("/proc/self/task"),descriptors=proc_entries("/proc/self/fd");
        sigset_t original,after; CHECK(pthread_sigmask(SIG_SETMASK,NULL,&original)==0);
        struct filter { unsigned short code; unsigned char jt,jf; unsigned int k; };
        struct filter filters[]={ {0x20,0,0,0}, {0x15,0,1,SYS_clone},
            {0x06,0,0,0x00050000U|EPERM}, {0x06,0,0,0x7fff0000U} };
        struct program { unsigned short count; struct filter *instructions; } program={4,filters};
        CHECK(syscall(SYS_prctl,38,1L,0L,0L,0L)==0 && syscall(SYS_prctl,22,2L,&program,0L,0L)==0);
        struct sigevent event={.sigev_notify=SIGEV_THREAD,.sigev_notify_function=thread_callback};
        errno=0; CHECK(mq_notify(-1,&event)==-1 && errno==EAGAIN);
        CHECK(pthread_sigmask(SIG_SETMASK,NULL,&after)==0);
        for(int signal=1;signal<=64;signal++) CHECK(sigismember(&original,signal)==sigismember(&after,signal));
        wait_retirement(tasks,descriptors); _Exit(0);
    }
    child_ok(child);
}
static void deadline_and_creation_bounds(void) {
    mqd_t queue=create_queue();
    struct mq_attr invalid={.mq_flags=1},old; memset(&old,0x55,sizeof old);
    errno=0; CHECK(mq_setattr(queue,&invalid,&old)==-1 && errno==EINVAL && old.mq_flags==0x5555555555555555L);
    struct timespec now,deadline; CHECK(clock_gettime(CLOCK_REALTIME,&deadline)==0); deadline.tv_nsec+=30000000;
    if(deadline.tv_nsec>=1000000000) { deadline.tv_nsec-=1000000000; deadline.tv_sec++; }
    char buffer[32]; errno=0;
    CHECK(mq_timedreceive(queue,buffer,sizeof buffer,NULL,&deadline)==-1 && errno==ETIMEDOUT);
    CHECK(clock_gettime(CLOCK_REALTIME,&now)==0 && (now.tv_sec>deadline.tv_sec || (now.tv_sec==deadline.tv_sec && now.tv_nsec>=deadline.tv_nsec)));
    CHECK(mq_send(queue,"a",1,0)==0 && mq_send(queue,"b",1,0)==0);
    CHECK(clock_gettime(CLOCK_REALTIME,&deadline)==0); deadline.tv_nsec+=30000000;
    if(deadline.tv_nsec>=1000000000) { deadline.tv_nsec-=1000000000; deadline.tv_sec++; }
    errno=0; CHECK(mq_timedsend(queue,"c",1,0,&deadline)==-1 && errno==ETIMEDOUT);
    CHECK(clock_gettime(CLOCK_REALTIME,&now)==0 && (now.tv_sec>deadline.tv_sec || (now.tv_sec==deadline.tv_sec && now.tv_nsec>=deadline.tv_nsec)));
    destroy_queue(queue);
    invalid=(struct mq_attr){.mq_maxmsg=0,.mq_msgsize=32}; errno=0;
    CHECK(mq_open(queue_name,O_CREAT|O_EXCL|O_RDWR,0600,&invalid)==-1 && errno==EINVAL);
    invalid=(struct mq_attr){.mq_maxmsg=2,.mq_msgsize=0}; errno=0;
    CHECK(mq_open(queue_name,O_CREAT|O_EXCL|O_RDWR,0600,&invalid)==-1 && errno==EINVAL);
    queue=mq_open(queue_name,O_CREAT|O_EXCL|O_RDWR,0600,NULL); CHECK(queue>=0);
    CHECK(mq_getattr(queue,&old)==0 && old.mq_maxmsg>0 && old.mq_msgsize>0);
    destroy_queue(queue);
}
static void inherited_unlinked_queue(void) {
    mqd_t queue=create_queue(); CHECK(mq_unlink(queue_name)==0);
    pid_t child=fork(); CHECK(child>=0);
    if(!child) { CHECK(mq_send(queue,"child",5,4)==0 && mq_close(queue)==0); _Exit(0); }
    child_ok(child); char buffer[32]; unsigned priority;
    CHECK(mq_receive(queue,buffer,sizeof buffer,&priority)==5 && priority==4 && !memcmp(buffer,"child",5));
    CHECK(mq_close(queue)==0);
}
static void *pending_transfer(void *argument) {
    struct waiter *waiter=argument; char buffer[32];
    CHECK(pthread_cancel(pthread_self())==0);
    struct timespec deadline=deadline_after(3);
    if(waiter->send) {
        if(waiter->timed) mq_timedsend(waiter->queue,"pending",7,0,&deadline);
        else mq_send(waiter->queue,"pending",7,0);
    } else {
        if(waiter->timed) mq_timedreceive(waiter->queue,buffer,sizeof buffer,NULL,&deadline);
        else mq_receive(waiter->queue,buffer,sizeof buffer,NULL);
    }
    CHECK(0); return NULL;
}
static void pending_transfer_cancellation(void) {
    for(int send=0;send<2;send++) for(int timed=0;timed<2;timed++) {
        mqd_t queue=create_queue(); if(!send) CHECK(mq_send(queue,"retained",8,0)==0);
        struct waiter waiter={.queue=queue,.send=send,.timed=timed};
        pthread_t thread; void *result; CHECK(pthread_create(&thread,NULL,pending_transfer,&waiter)==0);
        CHECK(pthread_join(thread,&result)==0 && result==PTHREAD_CANCELED);
        struct mq_attr attributes; CHECK(mq_getattr(queue,&attributes)==0 && attributes.mq_curmsgs==!send);
        destroy_queue(queue);
    }
}
static void direct_error_translation(void) {
    pid_t child=fork(); CHECK(child>=0);
    if(!child) {
        struct filter { unsigned short code; unsigned char jt,jf; unsigned int k; };
        struct filter filters[]={ {0x20,0,0,0}, {0x15,0,1,SYS_mq_unlink},
            {0x06,0,0,0x00050000U|EPERM}, {0x15,0,1,SYS_close},
            {0x06,0,0,0x00050000U|EINTR}, {0x06,0,0,0x7fff0000U} };
        struct program { unsigned short count; struct filter *instructions; } program={6,filters};
        CHECK(syscall(SYS_prctl,38,1L,0L,0L,0L)==0 && syscall(SYS_prctl,22,2L,&program,0L,0L)==0);
        errno=0; CHECK(mq_unlink("absent")==-1 && errno==EACCES);
        errno=0; CHECK(mq_close(-1)==-1 && errno==EINTR);
        _Exit(0);
    }
    child_ok(child);
}
int main(void) {
    names_attributes_transfer(); deadline_and_creation_bounds(); inherited_unlinked_queue();
    pending_transfer_cancellation(); direct_error_translation();
    for(int send=0;send<2;send++) for(int timed=0;timed<2;timed++) for(int completion=0;completion<3;completion++) blocking_transfer(send,timed,completion);
    signal_notifications(); thread_notifications(); creation_failure_cleanup();
    int tasks=proc_entries("/proc/self/task"),descriptors=proc_entries("/proc/self/fd");
    pthread_t thread; void *result; CHECK(pthread_create(&thread,NULL,pending_cancel,NULL)==0);
    CHECK(pthread_join(thread,&result)==0 && result==PTHREAD_CANCELED && pending_completed==1);
    wait_retirement(tasks,descriptors);
    puts("owned-message-queues-ok");
}
