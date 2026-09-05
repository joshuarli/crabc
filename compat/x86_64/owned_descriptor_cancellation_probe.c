#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>

/* musl 1.2.6 src/unistd/{pread,pwrite,preadv,pwritev,close,fsync,fdatasync}.c,
 * src/select/*.c, src/unistd/pause.c, src/signal/sigsuspend.c, and
 * src/linux/{epoll,eventfd}.c select the cancellation boundaries below.
 * Pipes, anonymous memfds, and event descriptors isolate every case. Public
 * FILE close deliberately retains src/stdio/__stdio_close.c's raw syscall. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"descriptor-cancel:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
enum immediate_operation { POSITIONED_READ, POSITIONED_WRITE, POSITIONED_READ_VECTOR,
    POSITIONED_WRITE_VECTOR, CLOSE_DESCRIPTOR, SYNC_DESCRIPTOR, SYNC_DATA, CLOSE_FILE };
struct immediate_state {
    enum immediate_operation operation;
    int fd, cancel_state;
    FILE *file;
    _Atomic int returned, cleanup, error, state_after;
};
static void immediate_cleanup(void *opaque) {
    struct immediate_state *s=opaque;
    atomic_store(&s->cleanup,1);
}
static void *immediate_worker(void *opaque) {
    struct immediate_state *s=opaque;
    char byte='K'; struct iovec vector={&byte,1};
    if (pthread_setcancelstate(s->cancel_state,NULL)) _exit(61);
    pthread_cleanup_push(immediate_cleanup,s);
    if (pthread_cancel(pthread_self())) _exit(62);
    errno=0;
    ssize_t result;
    switch(s->operation) {
    case POSITIONED_READ: result=pread(s->fd,&byte,1,0); break;
    case POSITIONED_WRITE: result=pwrite(s->fd,&byte,1,0); break;
    case POSITIONED_READ_VECTOR: result=preadv(s->fd,&vector,1,0); break;
    case POSITIONED_WRITE_VECTOR: result=pwritev(s->fd,&vector,1,0); break;
    case CLOSE_DESCRIPTOR: result=close(s->fd); break;
    case SYNC_DESCRIPTOR: result=fsync(s->fd); break;
    case SYNC_DATA: result=fdatasync(s->fd); break;
    case CLOSE_FILE: result=fclose(s->file); break;
    default: _exit(63);
    }
    atomic_store(&s->returned,1);
    atomic_store(&s->error,errno);
    int previous=-1;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous)) _exit(64);
    atomic_store(&s->state_after,previous);
    int expected_success=s->cancel_state==PTHREAD_CANCEL_DISABLE ||
        s->operation==CLOSE_FILE || (s->operation==CLOSE_DESCRIPTOR && s->cancel_state==2);
    if (expected_success) {
        ssize_t expected=s->operation<=POSITIONED_WRITE_VECTOR ? 1 : 0;
        if (result!=expected) _exit(65);
    } else if (s->cancel_state==2 && (result!=-1 || atomic_load(&s->error)!=ECANCELED)) _exit(66);
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return (void *)1;
}
static int exercise_immediate(enum immediate_operation operation, int cancel_state) {
    int fd=memfd_create("descriptor-cancellation",MFD_CLOEXEC); CHECK(fd>=0);
    CHECK(write(fd,"I",1)==1);
    struct immediate_state state={.operation=operation,.fd=fd,.cancel_state=cancel_state,.state_after=-1};
    if (operation==CLOSE_FILE) { state.file=fdopen(fd,"r+"); CHECK(state.file); }
    pthread_t worker; void *result=NULL;
    CHECK(!pthread_create(&worker,NULL,immediate_worker,&state));
    CHECK(!pthread_join(worker,&result) && result==PTHREAD_CANCELED && atomic_load(&state.cleanup));
    int should_return=cancel_state!=PTHREAD_CANCEL_ENABLE || operation==CLOSE_FILE;
    CHECK(atomic_load(&state.returned)==should_return);
    if (should_return) {
        int expected_state=cancel_state;
        if (cancel_state==2 && operation!=CLOSE_DESCRIPTOR && operation!=CLOSE_FILE) expected_state=PTHREAD_CANCEL_DISABLE;
        CHECK(atomic_load(&state.state_after)==expected_state);
    }
    int should_close=should_return && (operation==CLOSE_DESCRIPTOR || operation==CLOSE_FILE);
    if (should_close) { CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF); }
    else {
        char byte=0; CHECK(pread(fd,&byte,1,0)==1);
        int wrote=cancel_state==PTHREAD_CANCEL_DISABLE &&
            (operation==POSITIONED_WRITE || operation==POSITIONED_WRITE_VECTOR);
        CHECK(byte==(wrote ? 'K' : 'I'));
        CHECK(!close(fd));
    }
    printf("pending operation=%d state=%d returned=%d closed=%d\n",operation,cancel_state,should_return,should_close);
    return 0;
}

enum wait_operation { WAIT_POLL, WAIT_PPOLL, WAIT_SELECT, WAIT_PSELECT,
    WAIT_EPOLL, WAIT_EPOLL_MASK, WAIT_EVENT_READ, WAIT_EVENT_WRITE, WAIT_PAUSE, WAIT_SIGNAL };
struct wait_state {
    enum wait_operation operation;
    int fd;
    _Atomic int tid, cleanup, restored_mask;
};
static int temporary_mask_operation(enum wait_operation operation) {
    return operation==WAIT_PPOLL || operation==WAIT_PSELECT || operation==WAIT_EPOLL_MASK || operation==WAIT_SIGNAL;
}
static void wait_cleanup(void *opaque) {
    struct wait_state *s=opaque;
    sigset_t current;
    if (sigprocmask(SIG_SETMASK,NULL,&current)) _exit(71);
    atomic_store(&s->restored_mask,sigismember(&current,SIGUSR1)==1 && sigismember(&current,SIGUSR2)==0);
    atomic_store(&s->cleanup,1);
}
static void *wait_worker(void *opaque) {
    struct wait_state *s=opaque;
    sigset_t original, temporary;
    sigemptyset(&original); sigaddset(&original,SIGUSR1);
    sigemptyset(&temporary); sigaddset(&temporary,SIGUSR2);
    if (sigprocmask(SIG_SETMASK,&original,NULL)) _exit(72);
    struct pollfd descriptor={s->fd,POLLIN,0};
    fd_set readable; FD_ZERO(&readable); FD_SET(s->fd,&readable);
    struct epoll_event event;
    eventfd_t value=1;
    pthread_cleanup_push(wait_cleanup,s);
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    switch(s->operation) {
    case WAIT_POLL: poll(&descriptor,1,-1); break;
    case WAIT_PPOLL: ppoll(&descriptor,1,NULL,&temporary); break;
    case WAIT_SELECT: select(s->fd+1,&readable,NULL,NULL,NULL); break;
    case WAIT_PSELECT: pselect(s->fd+1,&readable,NULL,NULL,NULL,&temporary); break;
    case WAIT_EPOLL: epoll_wait(s->fd,&event,1,-1); break;
    case WAIT_EPOLL_MASK: epoll_pwait(s->fd,&event,1,-1,&temporary); break;
    case WAIT_EVENT_READ: eventfd_read(s->fd,&value); break;
    case WAIT_EVENT_WRITE: eventfd_write(s->fd,1); break;
    case WAIT_PAUSE: pause(); break;
    case WAIT_SIGNAL: sigsuspend(&temporary); break;
    }
    pthread_cleanup_pop(0);
    return (void *)1;
}
static int wait_in_syscall(struct wait_state *s, long expected) {
    const struct timespec pause={0,1000000};
    for (int retry=0;retry<2000;retry++) {
        int tid=atomic_load(&s->tid);
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
static int exercise_wait(enum wait_operation operation) {
    const long syscalls[]={SYS_poll,SYS_ppoll,SYS_select,SYS_pselect6,
        SYS_epoll_pwait,SYS_epoll_pwait,SYS_read,SYS_write,SYS_pause,SYS_rt_sigsuspend};
    int descriptors[2]; CHECK(!pipe(descriptors));
    struct wait_state state={.operation=operation,.fd=descriptors[0]};
    if (operation==WAIT_EPOLL || operation==WAIT_EPOLL_MASK) {
        state.fd=epoll_create1(EPOLL_CLOEXEC); CHECK(state.fd>=0);
        struct epoll_event event={.events=EPOLLIN,.data.fd=descriptors[0]};
        CHECK(!epoll_ctl(state.fd,EPOLL_CTL_ADD,descriptors[0],&event));
    } else if (operation==WAIT_EVENT_READ || operation==WAIT_EVENT_WRITE) {
        state.fd=eventfd(0,EFD_CLOEXEC); CHECK(state.fd>=0);
        if (operation==WAIT_EVENT_WRITE) CHECK(!eventfd_write(state.fd,UINT64_MAX-1));
    }
    pthread_t worker; void *result=NULL;
    CHECK(!pthread_create(&worker,NULL,wait_worker,&state));
    CHECK(wait_in_syscall(&state,syscalls[operation]));
    CHECK(!pthread_cancel(worker));
    CHECK(!pthread_join(worker,&result) && result==PTHREAD_CANCELED && atomic_load(&state.cleanup));
    CHECK(atomic_load(&state.restored_mask));
    if (state.fd!=descriptors[0]) CHECK(!close(state.fd));
    CHECK(!close(descriptors[0]) && !close(descriptors[1]));
    printf("blocked wait=%d canceled cleanup=1 temporary-mask=%d restored=1\n",operation,temporary_mask_operation(operation));
    return 0;
}
int main(void) {
    alarm(20);
    for (int operation=POSITIONED_READ;operation<=CLOSE_FILE;operation++) {
        for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) CHECK(!exercise_immediate(operation,state));
    }
    for (int operation=WAIT_POLL;operation<=WAIT_SIGNAL;operation++) CHECK(!exercise_wait(operation));
    puts("owned-descriptor-cancellation-ok");
    return 0;
}
