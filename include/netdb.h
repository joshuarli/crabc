#ifndef _NETDB_H
#define _NETDB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <stdint.h>
#include <sys/socket.h>

#define IPPORT_RESERVED 1024
#define AI_PASSIVE 0x0001
#define AI_CANONNAME 0x0002
#define AI_NUMERICHOST 0x0004
#define AI_V4MAPPED 0x0008
#define AI_ALL 0x0010
#define AI_ADDRCONFIG 0x0020
#define AI_NUMERICSERV 0x0400
#define NI_NUMERICHOST 0x01
#define NI_NUMERICSERV 0x02
#define NI_NOFQDN 0x04
#define NI_NAMEREQD 0x08
#define NI_DGRAM 0x10
#define NI_NUMERICSCOPE 0x100
#define EAI_AGAIN -3
#define EAI_BADFLAGS -1
#define EAI_FAIL -4
#define EAI_FAMILY -6
#define EAI_MEMORY -10
#define EAI_NONAME -2
#define EAI_SERVICE -8
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define EAI_NODATA -5
#define EAI_ADDRFAMILY -9
#endif
#define EAI_SOCKTYPE -7
#define EAI_SYSTEM -11
#define EAI_OVERFLOW -12
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define HOST_NOT_FOUND 1
#define TRY_AGAIN 2
#define NO_RECOVERY 3
#define NO_DATA 4
#define NO_ADDRESS NO_DATA
#endif

struct hostent { char *h_name; char **h_aliases; int h_addrtype; int h_length; char **h_addr_list; };
#define h_addr h_addr_list[0]
struct netent { char *n_name; char **n_aliases; int n_addrtype; uint32_t n_net; };
struct protoent { char *p_name; char **p_aliases; int p_proto; };
struct servent { char *s_name; char **s_aliases; int s_port; char *s_proto; };
struct addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};

void endhostent(void); void endnetent(void); void endprotoent(void); void endservent(void);
extern int h_errno;
int *__h_errno_location(void);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
void herror(const char *);
const char *hstrerror(int);
#endif
const char *gai_strerror(int);
struct hostent *gethostent(void);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
struct hostent *gethostbyaddr(const void *, socklen_t, int);
struct hostent *gethostbyname(const char *);
struct hostent *gethostbyname2(const char *, int);
int gethostbyaddr_r(const void *, socklen_t, int, struct hostent *, char *, size_t, struct hostent **, int *);
int gethostbyname_r(const char *, struct hostent *, char *, size_t, struct hostent **, int *);
int gethostbyname2_r(const char *, int, struct hostent *, char *, size_t, struct hostent **, int *);
#endif
struct netent *getnetbyaddr(uint32_t, int); struct netent *getnetbyname(const char *); struct netent *getnetent(void);
struct protoent *getprotobyname(const char *); struct protoent *getprotobynumber(int); struct protoent *getprotoent(void);
struct servent *getservbyname(const char *, const char *); struct servent *getservbyport(int, const char *); struct servent *getservent(void);
#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
int getservbyname_r(const char *, const char *, struct servent *, char *, size_t, struct servent **);
int getservbyport_r(int, const char *, struct servent *, char *, size_t, struct servent **);
#endif
void sethostent(int); void setnetent(int); void setprotoent(int); void setservent(int);
void freeaddrinfo(struct addrinfo *);
int getaddrinfo(const char *__restrict, const char *__restrict, const struct addrinfo *__restrict, struct addrinfo **__restrict);
int getnameinfo(const struct sockaddr *__restrict, socklen_t, char *__restrict, socklen_t, char *__restrict, socklen_t, int);

#ifdef __cplusplus
}
#endif

#endif
