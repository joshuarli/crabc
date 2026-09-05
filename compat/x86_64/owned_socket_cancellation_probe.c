#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>

/* Pinned musl 1.2.6 src/network/{connect,accept,accept4,send*,recv*}.c:
 * socket calls cancel at their source syscall, after message preparation.
 * The LP64 sendmmsg loop has no cancellation point for an empty vector.
 * All connections are private socketpairs or uniquely named abstract Unix
 * listeners; no network service, filesystem pathname, or fixed port is used. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"socket-cancel:%d errno=%d\n",__LINE__,errno); return 1; } } while (0)
enum operation { SEND_BYTES, SEND_TO, SEND_MESSAGE, SEND_BATCH, RECEIVE_BYTES,
    RECEIVE_FROM, RECEIVE_MESSAGE, RECEIVE_BATCH, ACCEPT_CONNECTION,
    ACCEPT_FLAGS, CONNECT_PEER, EMPTY_SEND_BATCH };
struct socket_state {
    enum operation operation;
    int fd, peer, listener, accepted, pending, cancel_state;
    struct sockaddr_un address;
    socklen_t address_length;
    char byte;
    _Atomic int tid, returned, result, error, state_after, cleanup;
};
static int sending(enum operation operation) { return operation<=SEND_BATCH || operation==EMPTY_SEND_BATCH; }
static void cleanup_socket(void *opaque) {
    struct socket_state *s=opaque;
    if (s->accepted>=0 && close(s->accepted)) _exit(51);
    if (close(s->fd)) _exit(52);
    atomic_store(&s->cleanup,1);
}
static void *socket_worker(void *opaque) {
    struct socket_state *s=opaque;
    struct iovec vector={&s->byte,1};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1};
    struct mmsghdr batch={.msg_hdr=message,.msg_len=0x12345678};
    if (pthread_setcancelstate(s->cancel_state,NULL)) _exit(53);
    pthread_cleanup_push(cleanup_socket,s);
    if (s->pending && pthread_cancel(pthread_self())) _exit(54);
    errno=90;
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    int result;
    switch(s->operation) {
    case SEND_BYTES: result=send(s->fd,&s->byte,1,MSG_NOSIGNAL); break;
    case SEND_TO: result=sendto(s->fd,&s->byte,1,MSG_NOSIGNAL,NULL,0); break;
    case SEND_MESSAGE: result=sendmsg(s->fd,&message,MSG_NOSIGNAL); break;
    case SEND_BATCH: result=sendmmsg(s->fd,&batch,1,MSG_NOSIGNAL); break;
    case RECEIVE_BYTES: result=recv(s->fd,&s->byte,1,0); break;
    case RECEIVE_FROM: result=recvfrom(s->fd,&s->byte,1,0,NULL,NULL); break;
    case RECEIVE_MESSAGE: result=recvmsg(s->fd,&message,0); break;
    case RECEIVE_BATCH: result=recvmmsg(s->fd,&batch,1,0,NULL); break;
    case ACCEPT_CONNECTION: result=accept(s->fd,NULL,NULL); break;
    case ACCEPT_FLAGS: result=accept4(s->fd,NULL,NULL,SOCK_CLOEXEC); break;
    case CONNECT_PEER: result=connect(s->fd,(struct sockaddr *)&s->address,s->address_length); break;
    case EMPTY_SEND_BATCH: result=sendmmsg(s->fd,&batch,0,MSG_NOSIGNAL); break;
    default: _exit(55);
    }
    atomic_store(&s->result,result);
    atomic_store(&s->error,errno);
    if ((s->operation==ACCEPT_CONNECTION || s->operation==ACCEPT_FLAGS) && result>=0) s->accepted=result;
    atomic_store(&s->returned,1);
    int previous=-1;
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,&previous)) _exit(56);
    atomic_store(&s->state_after,previous);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    return (void *)1;
}
static int listener_serial;
static int prepare_socket(struct socket_state *s, int blocked) {
    if (s->operation==ACCEPT_CONNECTION || s->operation==ACCEPT_FLAGS || s->operation==CONNECT_PEER) {
        s->listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(s->listener>=0);
        s->address.sun_family=AF_UNIX;
        int length=snprintf(s->address.sun_path+1,sizeof s->address.sun_path-1,
            "crabc-cancel-%ld-%d",(long)getpid(),listener_serial++);
        CHECK(length>0 && (size_t)length<sizeof s->address.sun_path-1);
        s->address_length=offsetof(struct sockaddr_un,sun_path)+1+length;
        CHECK(!bind(s->listener,(struct sockaddr *)&s->address,s->address_length));
        CHECK(!listen(s->listener,0));
        if (s->operation==CONNECT_PEER) {
            s->fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(s->fd>=0);
            if (!blocked) return 0;
        } else {
            s->fd=s->listener; s->listener=-1;
            if (blocked) return 0;
        }
        s->peer=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(s->peer>=0);
        CHECK(!connect(s->peer,(struct sockaddr *)&s->address,s->address_length));
        return 0;
    }
    int pair[2]; CHECK(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair));
    s->fd=pair[0]; s->peer=pair[1];
    if (blocked && sending(s->operation)) {
        char fill[4096]; memset(fill,'F',sizeof fill);
        while (send(s->fd,fill,sizeof fill,MSG_DONTWAIT|MSG_NOSIGNAL)>0) {}
        CHECK(errno==EAGAIN);
    } else if (!blocked && !sending(s->operation)) {
        CHECK(send(s->peer,"I",1,MSG_NOSIGNAL)==1);
    }
    return 0;
}
static int wait_in_syscall(struct socket_state *s, long expected) {
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
static int close_peers(struct socket_state *s) {
    if (s->peer>=0) CHECK(!close(s->peer));
    if (s->listener>=0) CHECK(!close(s->listener));
    return 0;
}
static int exercise_socket(enum operation operation, int cancel_state, int blocked, int timeout) {
    const long numbers[]={SYS_sendto,SYS_sendto,SYS_sendmsg,SYS_sendmsg,
        SYS_recvfrom,SYS_recvfrom,SYS_recvmsg,SYS_recvmmsg,SYS_accept,SYS_accept4,SYS_connect};
    struct socket_state state={.operation=operation,.fd=-1,.peer=-1,.listener=-1,.accepted=-1,
        .pending=!blocked,.cancel_state=cancel_state,.byte='K',.state_after=-1};
    CHECK(!prepare_socket(&state,blocked));
    if (timeout) {
        const struct timeval interval={30,0};
        CHECK(!setsockopt(state.fd,SOL_SOCKET,sending(operation) ? SO_SNDTIMEO : SO_RCVTIMEO,&interval,sizeof interval));
    }
    pthread_t worker; void *result=NULL;
    CHECK(!pthread_create(&worker,NULL,socket_worker,&state));
    if (blocked) {
        CHECK(wait_in_syscall(&state,numbers[operation]));
        CHECK(!pthread_cancel(worker));
    }
    CHECK(!pthread_join(worker,&result) && result==PTHREAD_CANCELED && atomic_load(&state.cleanup));
    int should_return=cancel_state!=PTHREAD_CANCEL_ENABLE || operation==EMPTY_SEND_BATCH;
    CHECK(atomic_load(&state.returned)==should_return);
    CHECK(fcntl(state.fd,F_GETFD)==-1 && errno==EBADF);
    if (should_return) {
        if (cancel_state==2 && operation!=EMPTY_SEND_BATCH) {
            CHECK(atomic_load(&state.result)==-1 && atomic_load(&state.error)==ECANCELED);
            CHECK(atomic_load(&state.state_after)==PTHREAD_CANCEL_DISABLE);
        } else {
            CHECK(atomic_load(&state.state_after)==cancel_state && atomic_load(&state.error)==90);
            int actual=atomic_load(&state.result);
            if (operation==ACCEPT_CONNECTION || operation==ACCEPT_FLAGS) CHECK(actual>=0);
            else CHECK(actual==((operation==CONNECT_PEER || operation==EMPTY_SEND_BATCH) ? 0 : 1));
        }
    }
    if (operation>=RECEIVE_BYTES && operation<=RECEIVE_BATCH)
        CHECK(state.byte==(cancel_state==PTHREAD_CANCEL_DISABLE ? 'I' : 'K'));
    CHECK(!close_peers(&state));
    printf("socket operation=%d state=%d blocked=%d timeout=%d canceled returned=%d\n",
        operation,cancel_state,blocked,timeout,should_return);
    return 0;
}
static _Atomic int signal_observed;
static void interrupt_handler(int signal) { (void)signal; atomic_store(&signal_observed,1); }
static void *interrupt_worker(void *opaque) {
    struct socket_state *s=opaque;
    errno=90;
    atomic_store(&s->tid,(int)syscall(SYS_gettid));
    int result=recv(s->fd,&s->byte,1,0);
    atomic_store(&s->result,result); atomic_store(&s->error,errno);
    cleanup_socket(s);
    return NULL;
}
static int exercise_restart(int timeout) {
    struct sigaction action={.sa_handler=interrupt_handler,.sa_flags=SA_RESTART}, previous;
    sigemptyset(&action.sa_mask); CHECK(!sigaction(SIGUSR1,&action,&previous));
    atomic_store(&signal_observed,0);
    struct socket_state state={.operation=RECEIVE_BYTES,.fd=-1,.peer=-1,.listener=-1,.accepted=-1};
    CHECK(!prepare_socket(&state,1));
    if (timeout) {
        const struct timeval interval={30,0};
        CHECK(!setsockopt(state.fd,SOL_SOCKET,SO_RCVTIMEO,&interval,sizeof interval));
    }
    pthread_t worker; CHECK(!pthread_create(&worker,NULL,interrupt_worker,&state));
    CHECK(wait_in_syscall(&state,SYS_recvfrom));
    CHECK(!syscall(SYS_tgkill,getpid(),atomic_load(&state.tid),SIGUSR1));
    while (!atomic_load(&signal_observed)) {}
    if (!timeout) {
        CHECK(wait_in_syscall(&state,SYS_recvfrom));
        CHECK(send(state.peer,"I",1,MSG_NOSIGNAL)==1);
    }
    CHECK(!pthread_join(worker,NULL));
    CHECK(atomic_load(&state.result)==(timeout ? -1 : 1));
    CHECK(atomic_load(&state.error)==(timeout ? EINTR : 90));
    CHECK(!close_peers(&state) && !sigaction(SIGUSR1,&previous,NULL));
    printf("socket user signal restart=%d errno-preserved=%d\n",!timeout,!timeout);
    return 0;
}
int main(void) {
    alarm(30);
    for (int operation=SEND_BYTES;operation<=EMPTY_SEND_BATCH;operation++)
        for (int state=PTHREAD_CANCEL_ENABLE;state<=2;state++) CHECK(!exercise_socket(operation,state,0,0));
    for (int operation=SEND_BYTES;operation<=CONNECT_PEER;operation++) CHECK(!exercise_socket(operation,PTHREAD_CANCEL_ENABLE,1,0));
    CHECK(!exercise_socket(SEND_BYTES,PTHREAD_CANCEL_ENABLE,1,1));
    CHECK(!exercise_socket(RECEIVE_BYTES,PTHREAD_CANCEL_ENABLE,1,1));
    CHECK(!exercise_restart(0) && !exercise_restart(1));
    puts("owned-socket-cancellation-ok");
    return 0;
}
