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
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define AF_NETLINK 16
#define AF_PACKET 17
#endif

#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define SOCK_RAW 3
#define SOCK_SEQPACKET 5
#define SOCK_CLOEXEC 02000000
#define SOCK_NONBLOCK 04000

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
#define SO_PROTOCOL 38
#define SO_DOMAIN 39
#define SOMAXCONN 128
#define MSG_OOB 1
#define MSG_PEEK 2
#define MSG_DONTROUTE 4
#define MSG_CTRUNC 8
#define MSG_TRUNC 0x20
#define MSG_EOR 0x80
#define MSG_WAITALL 0x100
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define MSG_WAITFORONE 0x10000
#endif
#define MSG_NOSIGNAL 0x4000
#define MSG_CMSG_CLOEXEC 0x40000000
#define SCM_RIGHTS 1

struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
#if __SIZEOF_LONG__ > 4 && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    int __pad1;
#endif
    int msg_iovlen;
#if __SIZEOF_LONG__ > 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    int __pad1;
#endif
    void *msg_control;
#if __SIZEOF_LONG__ > 4 && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    int __pad2;
#endif
    socklen_t msg_controllen;
#if __SIZEOF_LONG__ > 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    int __pad2;
#endif
    int msg_flags;
};
struct cmsghdr {
#if __SIZEOF_LONG__ > 4 && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    int __pad1;
#endif
    socklen_t cmsg_len;
#if __SIZEOF_LONG__ > 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    int __pad1;
#endif
    int cmsg_level;
    int cmsg_type;
};
struct linger { int l_onoff; int l_linger; };
#define __CMSG_ALIGN(len) (((len) + sizeof(long) - 1) & ~(sizeof(long) - 1))
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define CMSG_ALIGN(len) __CMSG_ALIGN(len)
#endif
#define CMSG_SPACE(len) (__CMSG_ALIGN(sizeof(struct cmsghdr)) + __CMSG_ALIGN(len))
#define CMSG_LEN(len) (__CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#define CMSG_DATA(cmsg) ((unsigned char *)(cmsg) + __CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_FIRSTHDR(msg) ((msg)->msg_controllen >= sizeof(struct cmsghdr) ? (struct cmsghdr *)(msg)->msg_control : (struct cmsghdr *)0)
#define CMSG_NXTHDR(msg, cmsg) \
    ((cmsg)->cmsg_len < sizeof(struct cmsghdr) || \
     (unsigned char *)(cmsg) + __CMSG_ALIGN((cmsg)->cmsg_len) + sizeof(struct cmsghdr) > \
         (unsigned char *)(msg)->msg_control + (msg)->msg_controllen \
         ? (struct cmsghdr *)0 \
         : (struct cmsghdr *)((unsigned char *)(cmsg) + __CMSG_ALIGN((cmsg)->cmsg_len)))

#ifdef _GNU_SOURCE
struct timespec;
struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};
#endif

int socket(int, int, int);
int socketpair(int, int, int, int[2]);
int bind(int, const struct sockaddr *, socklen_t);
int listen(int, int);
int accept(int, struct sockaddr *, socklen_t *);
int accept4(int, struct sockaddr *, socklen_t *, int);
int connect(int, const struct sockaddr *, socklen_t);
int getpeername(int, struct sockaddr *__restrict, socklen_t *__restrict);
int getsockopt(int, int, int, void *__restrict, socklen_t *__restrict);
ssize_t send(int, const void *, size_t, int);
ssize_t recv(int, void *, size_t, int);
ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t recvmsg(int, struct msghdr *, int);
ssize_t sendmsg(int, const struct msghdr *, int);
#ifdef _GNU_SOURCE
int sendmmsg(int, struct mmsghdr *, unsigned int, unsigned int);
int recvmmsg(int, struct mmsghdr *, unsigned int, unsigned int, struct timespec *);
#endif
int shutdown(int, int);
int setsockopt(int, int, int, const void *, socklen_t);
int getsockname(int, struct sockaddr *, socklen_t *);
int sockatmark(int);

#ifdef __cplusplus
}
#endif

#endif
