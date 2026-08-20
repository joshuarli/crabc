#ifndef _NETDB_H
#define _NETDB_H

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
#define NI_NOFQDN 0x01
#define NI_NUMERICHOST 0x02
#define NI_NAMEREQD 0x04
#define NI_NUMERICSERV 0x08
#define NI_NUMERICSCOPE 0x10
#define NI_DGRAM 0x10
#define EAI_AGAIN -3
#define EAI_BADFLAGS -1
#define EAI_FAIL -4
#define EAI_FAMILY -6
#define EAI_MEMORY -10
#define EAI_NONAME -2
#define EAI_SERVICE -8
#define EAI_SOCKTYPE -7
#define EAI_SYSTEM -11
#define EAI_OVERFLOW -12

struct hostent { char *h_name; char **h_aliases; int h_addrtype; int h_length; char **h_addr_list; };
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
const char *gai_strerror(int);
struct hostent *gethostent(void);
struct netent *getnetbyaddr(uint32_t, int); struct netent *getnetbyname(const char *); struct netent *getnetent(void);
struct protoent *getprotobyname(const char *); struct protoent *getprotobynumber(int); struct protoent *getprotoent(void);
struct servent *getservbyname(const char *, const char *); struct servent *getservbyport(int, const char *); struct servent *getservent(void);
void sethostent(int); void setnetent(int); void setprotoent(int); void setservent(int);
void freeaddrinfo(struct addrinfo *);
int getaddrinfo(const char *restrict, const char *restrict, const struct addrinfo *restrict, struct addrinfo **restrict);
int getnameinfo(const struct sockaddr *restrict, socklen_t, char *restrict, socklen_t, char *restrict, socklen_t, int);

#endif
