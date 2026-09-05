/* Oracle-only link wrappers observe the source's cancellation state around
 * TCP setup. Build with the ordinary cancellation probe object and --wrap;
 * these wrappers never enter an owned-product qualification link. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

int __real_setsockopt(int,int,int,const void *,socklen_t);
int __real_connect(int,const struct sockaddr *,socklen_t);
ssize_t __real_sendmsg(int,const struct msghdr *,int);
static int stream_fd=-1;
static int state(void) {
    int old;
    if(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)) abort();
    if(pthread_setcancelstate(old,0)) abort();
    return old;
}
int __wrap_setsockopt(int fd,int level,int option,const void *value,socklen_t length) {
    if(level==6 && option==30) {
        stream_fd=fd;
        dprintf(2,"tcp-fastopen-option state=%d\n",state());
        if(getenv("CRABC_TEST_NO_FASTOPEN")) { errno=ENOPROTOOPT;return -1; }
    }
    return __real_setsockopt(fd,level,option,value,length);
}
int __wrap_connect(int fd,const struct sockaddr *address,socklen_t length) {
    if(fd==stream_fd) dprintf(2,"tcp-connect state=%d\n",state());
    return __real_connect(fd,address,length);
}
ssize_t __wrap_sendmsg(int fd,const struct msghdr *message,int flags) {
    if(fd==stream_fd) dprintf(2,"tcp-sendmsg fastopen=%d state=%d\n",!!(flags&0x20000000),state());
    return __real_sendmsg(fd,message,flags);
}
