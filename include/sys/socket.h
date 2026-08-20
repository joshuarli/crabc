#ifndef _SYS_SOCKET_H
#define _SYS_SOCKET_H

#include <sys/types.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned short sa_family_t;
typedef unsigned int socklen_t;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

struct sockaddr_storage {
    sa_family_t ss_family;
    char __ss_padding[118];
    unsigned long __ss_align;
};

#define AF_UNSPEC 0
#define AF_UNIX   1
#define AF_INET   2
#define AF_INET6 10

#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define SOCK_RAW 3
#define SOCK_SEQPACKET 5

#define SHUT_RD   0
#define SHUT_WR   1
#define SHUT_RDWR 2

#define SOL_SOCKET    1
#define SO_REUSEADDR  2
#define SO_ACCEPTCONN 30
#define SO_BROADCAST 6
#define SO_DEBUG 1
#define SO_DONTROUTE 5
#define SO_ERROR 4
#define SO_KEEPALIVE 9
#define SO_LINGER 13
#define SO_OOBINLINE 10
#define SO_RCVBUF 8
#define SO_RCVLOWAT 18
#define SO_RCVTIMEO 20
#define SO_SNDBUF 7
#define SO_SNDLOWAT 19
#define SO_SNDTIMEO 21
#define SO_TYPE 3
#define SOMAXCONN 128
#define MSG_OOB 1
#define MSG_PEEK 2
#define MSG_DONTROUTE 4
#define MSG_CTRUNC 8
#define MSG_TRUNC 0x20
#define MSG_EOR 0x80
#define MSG_WAITALL 0x100
#define MSG_NOSIGNAL 0x4000
#define SCM_RIGHTS 1

struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    int msg_iovlen;
    void *msg_control;
    socklen_t msg_controllen;
    int msg_flags;
};
struct cmsghdr { socklen_t cmsg_len; int cmsg_level; int cmsg_type; };
struct linger { int l_onoff; int l_linger; };
#define CMSG_DATA(cmsg) ((unsigned char *)(cmsg) + sizeof(struct cmsghdr))
#define CMSG_FIRSTHDR(msg) ((msg)->msg_controllen >= sizeof(struct cmsghdr) ? (struct cmsghdr *)(msg)->msg_control : (struct cmsghdr *)0)
#define CMSG_NXTHDR(msg, cmsg) ((struct cmsghdr *)0)

int socket(int, int, int);
int socketpair(int, int, int, int[2]);
int bind(int, const struct sockaddr *, socklen_t);
int listen(int, int);
int accept(int, struct sockaddr *, socklen_t *);
int connect(int, const struct sockaddr *, socklen_t);
int getpeername(int, struct sockaddr *restrict, socklen_t *restrict);
int getsockopt(int, int, int, void *restrict, socklen_t *restrict);
ssize_t send(int, const void *, size_t, int);
ssize_t recv(int, void *, size_t, int);
ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t recvmsg(int, struct msghdr *, int);
ssize_t sendmsg(int, const struct msghdr *, int);
int shutdown(int, int);
int setsockopt(int, int, int, const void *, socklen_t);
int getsockname(int, struct sockaddr *, socklen_t *);
int sockatmark(int);

unsigned int htonl(unsigned int);
unsigned int ntohl(unsigned int);
unsigned short htons(unsigned short);
unsigned short ntohs(unsigned short);

#ifdef __cplusplus
}
#endif

#endif
