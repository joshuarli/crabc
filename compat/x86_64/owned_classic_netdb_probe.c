#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(c) do { if (!(c)) { dprintf(2,"classic netdb line %d errno %d h_errno %d\n",__LINE__,errno,h_errno); _exit(77); } } while (0)
static const char host_file[] =
    "198.51.100.10 canonical.test alias.test\n"
    "198.51.100.11 second.test alias.test\n"
    "2001:db8::10 ipv6.test alias.test\n"
    "192.0.2.20 v4only.test\n"
    "2001:db8::20 v6only.test\n"
    "::1 localhost6\n"
    "127.0.0.1 localhost\n"
    "2001:db8::77 global.test ordered.test\n"
    "fc00::77 private.test ordered.test\n"
    "::1 loopback.test ordered.test\n";
static const char service_file[] =
    "# isolated conventional services\n"
    "udp-first 45001/udp shared alt\n"
    "tcp-second 45001/tcp shared alt\n"
    "other 45002/tcp alias-service\n"
    "invalid 999999/tcp ignored\n"
    "bad x/tcp ignored\n"
    "twenty-character-name 45003/tcp long-alias\n"
    "proto-prefix 45004/tcpExtra prefix-alias\n";
static void file(const char *path,const char *bytes,size_t size) {
    int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0600); CHECK(fd>=0);
    CHECK(write(fd,bytes,size)==(ssize_t)size && close(fd)==0);
}
static void setup(void) {
    file("/etc/hosts",host_file,sizeof host_file-1);
    file("/etc/services",service_file,sizeof service_file-1);
    const char conf[]="nameserver 127.0.0.1\nnameserver 127.0.0.2\nnameserver 127.0.0.3\nsearch search.test\noptions ndots:1 timeout:1 attempts:1\n";
    file("/etc/resolv.conf",conf,sizeof conf-1);
}
static void address(struct hostent *h,unsigned index,int family,const char *text) {
    unsigned char expected[16]; CHECK(inet_pton(family,text,expected)==1);
    CHECK(h->h_addrtype==family && h->h_length==(family==AF_INET?4:16));
    CHECK(h->h_addr_list[index] && !memcmp(h->h_addr_list[index],expected,h->h_length));
}
static void contained(struct hostent *h,char *b,size_t n) {
    CHECK((uintptr_t)h->h_aliases%sizeof(char*)==0 && (uintptr_t)h->h_addr_list%sizeof(char*)==0);
    CHECK((char*)h->h_aliases>=b && (char*)h->h_aliases+3*sizeof(char*)<=b+n);
    CHECK((char*)h->h_addr_list>=b && (char*)h->h_addr_list<b+n);
    CHECK(h->h_name>=b && h->h_name<b+n && h->h_aliases[0]==h->h_name);
    for(char **p=h->h_aliases;*p;p++) CHECK(*p>=b && *p<b+n && memchr(*p,0,b+n-*p));
    for(char **p=h->h_addr_list;*p;p++) CHECK(*p>=b && *p+h->h_length<=b+n);
}
static void query_domain_construction(void) {
    unsigned char answer[512];
    char maximum[255];memset(maximum,'a',254);maximum[254]=0;
    maximum[63]=maximum[127]=maximum[191]='.';maximum[253]=0;
    errno=EDOM;h_errno=96;
    CHECK(res_mkquery(QUERY,maximum,C_IN,T_A,0,0,0,answer,sizeof answer)==271&&errno==EDOM&&h_errno==96);
    maximum[253]='.';
    CHECK(res_mkquery(QUERY,maximum,C_IN,T_A,0,0,0,answer,sizeof answer)==271&&errno==EDOM&&h_errno==96);
    maximum[253]='a';memset(answer,0xa5,sizeof answer);
    CHECK(res_mkquery(QUERY,maximum,C_IN,T_A,0,0,0,answer,sizeof answer)==-1&&errno==EDOM&&h_errno==96);
    for(unsigned i=0;i<sizeof answer;i++)CHECK(answer[i]==0xa5);
    char name[128],domain[128];
    memset(name,'a',sizeof name-1);name[63]='.';name[sizeof name-1]=0;
    memset(domain,'b',sizeof domain-1);domain[63]='.';domain[sizeof domain-1]=0;
    errno=EDOM;h_errno=96;
    CHECK(res_querydomain(name,domain,C_IN,T_A,answer,sizeof answer)==-1&&errno==EDOM&&h_errno==96);
    for(unsigned i=0;i<sizeof answer;i++)CHECK(answer[i]==0xa5);
    domain[126]=0;errno=EDOM;h_errno=96;
    CHECK(res_querydomain(name,domain,C_IN,T_A,answer,sizeof answer)==-1&&errno==EDOM&&h_errno==96);
    for(unsigned i=0;i<sizeof answer;i++)CHECK(answer[i]==0xa5);
    /* Joining always contributes a dot, even when the supplied name already
       ends in one. Query construction then rejects the empty interior label. */
    const char *names[]={"a.","a.",""};
    const char *domains[]={"example.test","","example.test"};
    for(unsigned n=0;n<3;n++) {
        errno=EDOM;h_errno=96;
        CHECK(res_querydomain(names[n],domains[n],C_IN,T_A,answer,sizeof answer)==-1&&errno==EDOM&&h_errno==96);
        for(unsigned i=0;i<sizeof answer;i++)CHECK(answer[i]==0xa5);
    }
    errno=EDOM;h_errno=96;
    CHECK(res_query("a..example.test",C_IN,T_A,answer,sizeof answer)==-1&&errno==EDOM&&h_errno==96);
    for(unsigned i=0;i<sizeof answer;i++)CHECK(answer[i]==0xa5);
}
static void host_numeric(void) {
    query_domain_construction();
    struct hostent h,*r;_Alignas(16) char b[2048];int error;
    const char *names[]={"127.0.0.1","127.1","0x7f000001","0177.0.0.1"};
    for(unsigned i=0;i<4;i++) {
        error=97;h_errno=96;errno=EDOM;r=(void*)1;
        CHECK(gethostbyname_r(names[i],&h,b,sizeof b,&r,&error)==0 && r==&h && error==97 && h_errno==96 && errno==EDOM);
        CHECK(!strcmp(h.h_name,names[i]) && !h.h_aliases[1] && !h.h_addr_list[1]);contained(&h,b,sizeof b);address(&h,0,AF_INET,"127.0.0.1");
    }
    struct hostent *owned=gethostbyname2("2001:db8::42",AF_INET6);CHECK(owned);address(owned,0,AF_INET6,"2001:db8::42");
    CHECK(!gethostbyname2_r("2001:db8::42",AF_INET6,&h,b,sizeof b,&r,&error) && r==&h);address(&h,0,AF_INET6,"2001:db8::42");
    CHECK(!gethostbyname2_r("fe80::1%1",AF_INET6,&h,b,sizeof b,&r,&error) && r==&h);address(&h,0,AF_INET6,"fe80::1");
    error=97;CHECK(!gethostbyname2_r("127.1",AF_INET6,&h,b,0,&r,&error) && !r && error==NO_DATA);
    error=97;CHECK(!gethostbyname2_r("::1",AF_INET,&h,b,0,&r,&error) && !r && error==NO_DATA);
    error=97;CHECK(!gethostbyname_r("",&h,b,0,&r,&error) && !r && error==HOST_NOT_FOUND);
    char long_name[256];memset(long_name,'a',255);long_name[255]=0;
    error=97;CHECK(!gethostbyname_r(long_name,&h,b,0,&r,&error) && !r && error==HOST_NOT_FOUND);
}
static void host_local(void) {
    struct hostent h,*r;char b[4096];int error=97;h_errno=96;
    CHECK(!gethostbyname_r("alias.test",&h,b,sizeof b,&r,&error) && r==&h && error==97 && h_errno==96);
    CHECK(!strcmp(h.h_name,"canonical.test") && !strcmp(h.h_aliases[1],"alias.test") && !h.h_aliases[2]);
    address(&h,0,AF_INET,"198.51.100.10");address(&h,1,AF_INET,"198.51.100.11");CHECK(!h.h_addr_list[2]);contained(&h,b,sizeof b);
    CHECK(!gethostbyname2_r("alias.test",AF_INET6,&h,b,sizeof b,&r,&error) && r==&h);
    CHECK(!strcmp(h.h_name,"canonical.test"));address(&h,0,AF_INET6,"2001:db8::10");
    CHECK(!gethostbyname2_r("v4only.test",AF_INET6,&h,b,sizeof b,&r,&error) && !r && error==NO_DATA);
    CHECK(!gethostbyname2_r("ordered.test",AF_INET6,&h,b,sizeof b,&r,&error) && r==&h);
    address(&h,0,AF_INET6,"::1");address(&h,1,AF_INET6,"2001:db8::77");address(&h,2,AF_INET6,"fc00::77");
    CHECK(!gethostbyname_r("ALIAS.TEST",&h,b,sizeof b,&r,&error) && !r && error==HOST_NOT_FOUND);
}
static void host_buffers(void) {
    _Alignas(16) unsigned char raw[2048];struct hostent h,*r;int error;
    for(unsigned offset=0;offset<8;offset++) {
        char *b=(char*)raw+offset;size_t align=-(uintptr_t)b&7;
        size_t need=4*sizeof(char*)+3*(sizeof(char*)+4)+strlen("alias.test")+1+strlen("canonical.test")+1+align;
        memset(raw,0x5a,sizeof raw);memset(&h,0x6b,sizeof h);error=97;h_errno=96;
        CHECK(gethostbyname_r("alias.test",&h,b,need-1,&r,&error)==ERANGE && !r && error==97 && h_errno==96);
        CHECK(h.h_addrtype==AF_INET && h.h_length==4);
        for(unsigned i=0;i<sizeof raw;i++) CHECK(raw[i]==0x5a);
        CHECK(!gethostbyname_r("alias.test",&h,b,need,&r,&error) && r==&h && error==97);contained(&h,b,need);
        CHECK(h.h_aliases==(void*)(b+align) && h.h_addr_list==h.h_aliases+3);
        CHECK(h.h_addr_list[0]==(char*)(h.h_addr_list+3));
    }
}
static void host_many(void) {
    FILE *f=fopen("/etc/hosts","w");CHECK(f);
    for(unsigned i=1;i<=50;i++)CHECK(fprintf(f,"192.0.2.%u many.test\n",i)>0);CHECK(!fclose(f));
    struct hostent h,*r;char b[4096];int error=97;
    CHECK(!gethostbyname_r("many.test",&h,b,sizeof b,&r,&error)&&r==&h);
    unsigned count=0;while(h.h_addr_list[count])count++;CHECK(count==48);
    address(&h,0,AF_INET,"192.0.2.1");address(&h,47,AF_INET,"192.0.2.48");
    struct hostent *p=gethostbyname("many.test");CHECK(p);count=0;while(p->h_addr_list[count])count++;CHECK(count==48);
}
static void query_domain_answers(void) {
    unsigned char answer[512];
    const struct {const char *name,*domain,*address;int type,family,answers;} cases[]={
        {"a","example.test","198.51.100.42",T_A,AF_INET,1},
        {"a.example.test","","198.51.100.42",T_A,AF_INET,1},
        {"aaaa","example.test","2001:db8::42",T_AAAA,AF_INET6,1},
        {"alias","example.test","198.51.100.44",T_A,AF_INET,2},
        {"tc","example.test","198.51.100.45",T_A,AF_INET,1},
        {"fallback","example.test","198.51.100.18",T_A,AF_INET,1},
    };
    for(unsigned i=0;i<sizeof cases/sizeof cases[0];i++) {
        h_errno=96;
        int length=res_querydomain(cases[i].name,cases[i].domain,C_IN,cases[i].type,answer,sizeof answer);
        CHECK(length>12&&length<=(int)sizeof answer&&h_errno==96);
        CHECK((answer[3]&15)==0&&answer[6]==0&&answer[7]==cases[i].answers);
        unsigned char expected[16];int size=cases[i].family==AF_INET?4:16;
        CHECK(inet_pton(cases[i].family,cases[i].address,expected)==1);
        CHECK(!memcmp(answer+length-size,expected,size));
    }
    struct addrinfo hints={.ai_family=AF_INET,.ai_socktype=SOCK_STREAM,.ai_flags=AI_CANONNAME},*alias=0,*batch=0,*search=0;
    CHECK(!getaddrinfo("alias.example.test","80",&hints,&alias)&&alias&&!alias->ai_next);
    CHECK(!strcmp(alias->ai_canonname,"target.example.test"));
    hints.ai_family=AF_UNSPEC;
    CHECK(!getaddrinfo("batch.example.test","80",&hints,&batch)&&batch);
    int v4=0,v6=0;
    for(struct addrinfo *p=batch;p;p=p->ai_next) {
        if(p->ai_family==AF_INET) {CHECK(((struct sockaddr_in*)p->ai_addr)->sin_addr.s_addr==inet_addr("198.51.100.48"));v4++;}
        else if(p->ai_family==AF_INET6) {
            unsigned char expected[16];CHECK(inet_pton(AF_INET6,"2001:db8::48",expected)==1);
            CHECK(!memcmp(&((struct sockaddr_in6*)p->ai_addr)->sin6_addr,expected,16));v6++;
        } else CHECK(0);
    }
    CHECK(v4==1&&v6==1);freeaddrinfo(batch);
    hints.ai_family=AF_INET;
    CHECK(!getaddrinfo("searchhost","80",&hints,&search)&&search&&!search->ai_next);
    CHECK(!strcmp(search->ai_canonname,"searchhost.search.test"));
    CHECK(((struct sockaddr_in*)search->ai_addr)->sin_addr.s_addr==inet_addr("198.51.100.17"));
    freeaddrinfo(search);
    /* Later lookups and freeing their results do not retire the earlier
       caller-owned canonical name or address list. */
    CHECK(!strcmp(alias->ai_canonname,"target.example.test"));
    CHECK(((struct sockaddr_in*)alias->ai_addr)->sin_addr.s_addr==inet_addr("198.51.100.44"));
    freeaddrinfo(alias);
}

static void host_dns(void) {
    query_domain_answers();
    struct hostent h,*r;char b[2048];int error=97;
    CHECK(!gethostbyname_r("a.example.test.",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);address(&h,0,AF_INET,"198.51.100.42");CHECK(!strcmp(h.h_name,"a.example.test"));
    CHECK(!gethostbyname2_r("aaaa.example.test",AF_INET6,&h,b,sizeof b,&r,&error)&&r==&h);address(&h,0,AF_INET6,"2001:db8::42");
    CHECK(!gethostbyname_r("alias.example.test",&h,b,sizeof b,&r,&error)&&r==&h);CHECK(!strcmp(h.h_name,"target.example.test"));address(&h,0,AF_INET,"198.51.100.44");
    CHECK(!gethostbyname_r("malformed.example.test",&h,b,sizeof b,&r,&error)&&r==&h);address(&h,0,AF_INET,"198.51.100.43");
    CHECK(!gethostbyname_r("tc.example.test",&h,b,sizeof b,&r,&error)&&r==&h);address(&h,0,AF_INET,"198.51.100.45");
    CHECK(!gethostbyname_r("fallback.example.test",&h,b,sizeof b,&r,&error)&&r==&h);address(&h,0,AF_INET,"198.51.100.18");
    CHECK(!gethostbyname_r("searchhost",&h,b,sizeof b,&r,&error)&&r==&h);CHECK(!strcmp(h.h_name,"searchhost.search.test"));
    CHECK(!gethostbyname_r("nxdomain.example.test",&h,b,0,&r,&error)&&!r&&error==HOST_NOT_FOUND);
    CHECK(!gethostbyname_r("nodata.example.test",&h,b,0,&r,&error)&&!r&&error==NO_DATA);
}
static void dns_record_order(void) {
    struct hostent h,*r;char b[4096];int error=97;
    /* musl keeps the first A and the default canonical spelling: its callback
       stops at the complete-but-five-byte selected A before the late CNAME. */
    CHECK(!gethostbyname_r("order-after.example.test",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    CHECK(!strcmp(h.h_name,"order-after.example.test"));address(&h,0,AF_INET,"198.51.100.46");CHECK(!h.h_addr_list[1]);
    /* A CNAME handled before the malformed selected A remains the canonical
       spelling; the later CNAME is beyond the source callback's stop point. */
    CHECK(!gethostbyname_r("order-before.example.test",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    CHECK(!strcmp(h.h_name,"early.example.test"));address(&h,0,AF_INET,"198.51.100.46");CHECK(!h.h_addr_list[1]);
    /* A malformed selected A before every address stops with NO_DATA. */
    CHECK(!gethostbyname_r("order-empty.example.test",&h,b,0,&r,&error)&&!r&&error==NO_DATA);
    /* The callback processes CNAME before its MAXADDRS guard: the 49th bad A
       is ignored after the cap, while the following CNAME still replaces canon. */
    error=97;
    CHECK(!gethostbyname_r("order-cap.example.test",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    unsigned count=0;while(h.h_addr_list[count])count++;CHECK(count==48&&!strcmp(h.h_name,"cap.example.test"));
    address(&h,0,AF_INET,"192.0.2.1");address(&h,47,AF_INET,"192.0.2.48");
    /* The same selected-RDLENGTH stop applies to AAAA's required 16 bytes. */
    error=97;
    CHECK(!gethostbyname2_r("order-aaaa.example.test",AF_INET6,&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    CHECK(!strcmp(h.h_name,"order-aaaa.example.test"));address(&h,0,AF_INET6,"2001:db8::46");CHECK(!h.h_addr_list[1]);
}
static void dns_record_prefix(void) {
    struct hostent h,*r;char b[4096];int error=97;
    /* musl accepts this matching UDP response, retains its complete CNAME/A
       callbacks, then ignores __dns_parse's late physical-RR failure. */
    CHECK(!gethostbyname_r("prefix-a.example.test",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    CHECK(!strcmp(h.h_name,"early.example.test"));address(&h,0,AF_INET,"198.51.100.47");CHECK(!h.h_addr_list[1]);
    /* The owned modern entry uses the same lookup backend and canonical name. */
    struct addrinfo hint={.ai_family=AF_INET,.ai_flags=AI_CANONNAME},*ai=(void*)1;
    CHECK(!getaddrinfo("prefix-a.example.test","80",&hint,&ai)&&ai&&!strcmp(ai->ai_canonname,"early.example.test"));
    CHECK(((struct sockaddr_in*)ai->ai_addr)->sin_addr.s_addr==inet_addr("198.51.100.47"));freeaddrinfo(ai);
    unsigned char query[512],answer[512];
    int query_length=res_mkquery(0,"prefix-a.example.test",C_IN,T_A,0,0,0,query,sizeof query);
    CHECK(query_length>0);
    int full_length=res_send(query,query_length,answer,sizeof answer);
    CHECK(full_length>16&&answer[6]==0&&answer[7]==3);
    unsigned char short_answer[18];memset(short_answer,0xa5,sizeof short_answer);
    CHECK(res_send(query,query_length,short_answer,0)==full_length&&short_answer[0]==0xa5);
    CHECK(res_send(query,query_length,short_answer,1)==full_length&&
          short_answer[0]==answer[0]&&short_answer[1]==0xa5);
    CHECK(res_send(query,query_length,short_answer,16)==full_length&&
          !memcmp(short_answer,answer,16)&&short_answer[16]==0xa5);
    h_errno=97;
    CHECK(res_query("prefix-a.example.test",C_IN,T_A,answer,sizeof answer)>12&&answer[6]==0&&answer[7]==3);
    CHECK(h_errno==97);
    CHECK(res_query("prefix-a.example.test",256,T_A,answer,sizeof answer)==-1);
    CHECK(h_errno==97);
    error=97;
    CHECK(!gethostbyname2_r("prefix-aaaa.example.test",AF_INET6,&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    CHECK(!strcmp(h.h_name,"early.example.test"));address(&h,0,AF_INET6,"2001:db8::47");CHECK(!h.h_addr_list[1]);
    error=97;
    CHECK(!gethostbyname_r("prefix-authority.example.test",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    CHECK(!strcmp(h.h_name,"early.example.test"));address(&h,0,AF_INET,"198.51.100.47");CHECK(!h.h_addr_list[1]);
    /* A complete late RR header with short RDATA stops after the same prefix. */
    error=97;
    CHECK(!gethostbyname_r("prefix-rdata.example.test",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    CHECK(!strcmp(h.h_name,"early.example.test"));address(&h,0,AF_INET,"198.51.100.47");CHECK(!h.h_addr_list[1]);
    /* The source answer callback ignores a physically short additional RR. */
    error=97;
    CHECK(!gethostbyname_r("prefix-additional.example.test",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    CHECK(!strcmp(h.h_name,"early.example.test"));address(&h,0,AF_INET,"198.51.100.47");CHECK(!h.h_addr_list[1]);
    /* A physical answer tail before every callback retains no data rather than
       treating this received response as a transport retry. */
    error=97;
    CHECK(!gethostbyname_r("prefix-empty.example.test",&h,b,0,&r,&error)&&!r&&error==NO_DATA);
    struct addrinfo no_data_hint={.ai_family=AF_INET},*no_data=(void*)1;
    CHECK(getaddrinfo("prefix-empty.example.test","80",&no_data_hint,&no_data)==EAI_NODATA&&no_data==(void*)1);
    query_length=res_mkquery(0,"prefix-empty.example.test",C_IN,T_A,0,0,0,query,sizeof query);
    CHECK(query_length>0&&res_send(query,query_length,answer,sizeof answer)>12
          &&(answer[3]&15)==0&&answer[6]==0&&answer[7]==1);
    CHECK(res_query("prefix-empty.example.test",C_IN,T_A,answer,sizeof answer)>12
          &&(answer[3]&15)==0&&answer[6]==0&&answer[7]==1);
    /* TC still takes the established complete TCP-frame path; only the RR
       tail is physically short. */
    error=97;
    CHECK(!gethostbyname_r("prefix-tcp.example.test",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    CHECK(!strcmp(h.h_name,"early.example.test"));address(&h,0,AF_INET,"198.51.100.47");CHECK(!h.h_addr_list[1]);
    struct sockaddr_in sa={.sin_family=AF_INET};char node[256];
    CHECK(inet_pton(AF_INET,"198.51.100.47",&sa.sin_addr)==1);
    CHECK(!getnameinfo((void*)&sa,sizeof sa,node,sizeof node,0,0,NI_NAMEREQD)&&!strcmp(node,"physical.example.test"));
}
static void dns_batch(void) {
    struct addrinfo hint={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM},*result=0;
    CHECK(!getaddrinfo("batch.example.test","80",&hint,&result)&&result);
    int v4=0,v6=0;
    for(struct addrinfo *p=result;p;p=p->ai_next) {
        if(p->ai_family==AF_INET) {
            CHECK(((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr==inet_addr("198.51.100.48"));v4++;
        } else if(p->ai_family==AF_INET6) {
            unsigned char expected[16];CHECK(inet_pton(AF_INET6,"2001:db8::48",expected)==1);
            CHECK(!memcmp(&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr,expected,16));v6++;
        } else CHECK(0);
    }
    CHECK(v4==1&&v6==1);freeaddrinfo(result);
    /* A UDP frame longer than this C reply slot has no TC bit.  The selected
       source batch must validate its copied question prefix, start TCP for A,
       and still retain the same-round AAAA UDP answer. */
    result=0;CHECK(!getaddrinfo("batch-mixed.example.test","80",&hint,&result)&&result);v4=v6=0;
    for(struct addrinfo *p=result;p;p=p->ai_next) {
        if(p->ai_family==AF_INET) {
            CHECK(((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr==inet_addr("198.51.100.49"));v4++;
        } else if(p->ai_family==AF_INET6) {
            unsigned char expected[16];CHECK(inet_pton(AF_INET6,"2001:db8::49",expected)==1);
            CHECK(!memcmp(&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr,expected,16));v6++;
        } else CHECK(0);
    }
    CHECK(v4==1&&v6==1);freeaddrinfo(result);
    /* A same-ID response with a changed question is not an associated reply. */
    struct hostent h,*r;char b[2048];int error=97;
    CHECK(!gethostbyname_r("wrong-association.example.test",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    char association[INET_ADDRSTRLEN];
    CHECK(inet_ntop(AF_INET,h.h_addr_list[0],association,sizeof association));
    printf("wrong-association=%s\n",association);CHECK(!h.h_addr_list[1]);
    /* REFUSED is ignored while the configured fallback's positive response is
       still eligible in this round. */
    error=97;CHECK(!gethostbyname_r("refused.example.test",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);
    address(&h,0,AF_INET,"198.51.100.52");CHECK(!h.h_addr_list[1]);
    /* The first all-server A/AAAA broadcast deliberately receives nothing;
       source's integer retry scheduler broadcasts both unresolved slots again. */
    const char retry_conf[]="nameserver 127.0.0.1\nnameserver 127.0.0.2\nnameserver 127.0.0.3\noptions ndots:1 timeout:1 attempts:2\n";
    file("/etc/resolv.conf",retry_conf,sizeof retry_conf-1);
    result=0;CHECK(!getaddrinfo("batch-retry.example.test","80",&hint,&result)&&result);v4=v6=0;
    for(struct addrinfo *p=result;p;p=p->ai_next) {
        if(p->ai_family==AF_INET) { CHECK(((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr==inet_addr("198.51.100.51"));v4++; }
        else if(p->ai_family==AF_INET6) { unsigned char expected[16];CHECK(inet_pton(AF_INET6,"2001:db8::51",expected)==1);CHECK(!memcmp(&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr,expected,16));v6++; }
        else CHECK(0);
    }
    CHECK(v4==1&&v6==1);freeaddrinfo(result);
}
static void search_precedence(void) {
    struct hostent h,*r;char b[2048];int error=97;
    CHECK(!gethostbyname_r("stop",&h,b,sizeof b,&r,&error)&&!r&&error==NO_DATA);
    CHECK(!gethostbyname_r("bare",&h,b,sizeof b,&r,&error)&&r==&h&&!strcmp(h.h_name,"bare"));
    CHECK(!gethostbyname_r("plain.test",&h,b,sizeof b,&r,&error)&&!r&&error==HOST_NOT_FOUND);
    CHECK(gethostbyname_r("servfail.example.test",&h,b,0,&r,&error)==EAGAIN&&!r&&error==TRY_AGAIN);
}
static void mixed_family_precedence(void) {
    const char conf[]="nameserver 127.0.0.1\nsearch search.test\noptions ndots:1 timeout:1 attempts:1\n";
    file("/etc/resolv.conf",conf,sizeof conf-1);
    struct addrinfo hint={.ai_family=AF_UNSPEC,.ai_socktype=SOCK_STREAM},*result=(void*)1;
    CHECK(getaddrinfo("mixed-nx.example.test","80",&hint,&result)==EAI_NONAME&&result==(void*)1);
    CHECK(getaddrinfo("mixed-timeout.example.test","80",&hint,&result)==EAI_AGAIN&&result==(void*)1);
    CHECK(getaddrinfo("mixed-search","80",&hint,&result)==0&&result&&result->ai_family==AF_INET&&!result->ai_next);
    unsigned char expected[4]={192,0,2,93};
    CHECK(!memcmp(&((struct sockaddr_in*)result->ai_addr)->sin_addr,expected,4));
    CHECK(!strcmp(result->ai_canonname,"mixed-search"));freeaddrinfo(result);
}
static void reverse_local(void) {
    unsigned char ip[16];struct hostent h,*r;char b[1024];int error=97;h_errno=96;
    CHECK(inet_pton(AF_INET,"198.51.100.10",ip)==1);
    CHECK(!gethostbyaddr_r(ip,4,AF_INET,&h,b,sizeof b,&r,&error)&&r==&h&&error==97&&h_errno==96);
    CHECK(!strcmp(h.h_name,"canonical.test")&&h.h_aliases[0]==h.h_name&&!h.h_aliases[1]&&!h.h_addr_list[1]);address(&h,0,AF_INET,"198.51.100.10");
    CHECK(inet_pton(AF_INET6,"::ffff:198.51.100.10",ip)==1);
    CHECK(!gethostbyaddr_r(ip,16,AF_INET6,&h,b,sizeof b,&r,&error)&&r==&h&&!strcmp(h.h_name,"canonical.test"));
    error=97;errno=EDOM;CHECK(gethostbyaddr_r(ip,4,AF_INET6,&h,b,0,&r,&error)==EINVAL&&!r&&error==NO_RECOVERY&&errno==EDOM);
    error=97;CHECK(gethostbyaddr_r(ip,16,AF_UNIX,&h,b,0,&r,&error)==EINVAL&&!r&&error==NO_RECOVERY);
    error=97;CHECK(gethostbyaddr_r(ip,16,AF_INET6,&h,b,0,&r,&error)==ERANGE&&!r&&error==97);
}
static void reverse_dns(void) {
    unsigned char ip[16];struct hostent h,*r;char b[1024];int error=97;
    CHECK(inet_pton(AF_INET,"198.51.100.42",ip)==1);
    CHECK(!gethostbyaddr_r(ip,4,AF_INET,&h,b,sizeof b,&r,&error)&&r==&h&&error==97&&!strcmp(h.h_name,"reverse.example.test"));
    CHECK(inet_pton(AF_INET6,"2001:db8::42",ip)==1);
    CHECK(!gethostbyaddr_r(ip,16,AF_INET6,&h,b,sizeof b,&r,&error)&&r==&h&&!strcmp(h.h_name,"reverse6.example.test"));
    CHECK(inet_pton(AF_INET,"192.0.2.99",ip)==1);
    CHECK(!gethostbyaddr_r(ip,4,AF_INET,&h,b,sizeof b,&r,&error)&&r==&h&&!strcmp(h.h_name,"192.0.2.99"));
    struct sockaddr_in sa={.sin_family=AF_INET};memcpy(&sa.sin_addr,ip,4);
    CHECK(getnameinfo((void*)&sa,sizeof sa,b,sizeof b,0,0,NI_NAMEREQD)==EAI_NONAME);
    CHECK(getnameinfo((void*)&sa,sizeof sa,b,0,0,0,NI_NAMEREQD)==0);
    CHECK(getnameinfo((void*)&sa,sizeof sa,b,sizeof b,0,0,NI_NUMERICHOST|0x40000000)==0&&!strcmp(b,"192.0.2.99"));
}
static void services(void) {
    struct servent s,*r;_Alignas(16) char b[128];char requested[]="alt",tcp[]="tcp",udp[]="udp";
    errno=EDOM;setservent(1);CHECK(errno==EDOM);CHECK(!getservent()&&errno==EDOM);
    endservent();CHECK(errno==EDOM);
    CHECK(!getservbyname_r(requested,0,&s,b,sizeof b,&r)&&r==&s&&s.s_name==requested&&s.s_aliases[0]==requested&&!s.s_aliases[1]&&s.s_port==htons(45001)&&!strcmp(s.s_proto,"udp"));
    CHECK(!getservbyname_r(requested,tcp,&s,b,sizeof b,&r)&&r==&s&&s.s_name==requested&&s.s_proto!=tcp&&!strcmp(s.s_proto,"tcp"));
    CHECK(!getservbyname_r("prefix-alias",tcp,&s,b,sizeof b,&r)&&r==&s&&s.s_port==htons(45004));
    CHECK(!getservbyport_r(htons(45001),0,&s,b,sizeof b,&r)&&r==&s&&!strcmp(s.s_name,"tcp-second"));
    CHECK(!getservbyport_r(htons(45001),udp,&s,b,sizeof b,&r)&&r==&s&&s.s_proto==udp&&!strcmp(s.s_name,"udp-first")&&s.s_aliases[0]==s.s_name&&!s.s_aliases[1]);
    struct servent *byname=getservbyname(requested,tcp);CHECK(byname&&byname->s_name==requested);
    struct servent *byport=getservbyport(htons(45001),tcp);CHECK(byport&&byport!=byname&&!strcmp(byport->s_name,"tcp-second")&&byname->s_name==requested);
    CHECK(!getservbyport(htons(45003),tcp));CHECK(!getservbyport_r(htons(45003),tcp,&s,b,sizeof b,&r)&&r==&s&&!strcmp(s.s_name,"twenty-character-name"));

    /* Each lookup opens the current services file; successful legacy calls
     * reuse their result record when the file contents change. */
    struct servent *shared_name=getservbyname("alt",tcp);
    struct servent *shared_port=getservbyport(htons(45001),tcp);
    CHECK(shared_name&&shared_port&&shared_name!=shared_port);
    const char replacement[]="first 45005/tcp current\nsecond 45006/udp current\n";
    file("/etc/services",replacement,sizeof replacement-1);
    CHECK(getservbyname_r("alt",tcp,&s,b,sizeof b,&r)==ENOENT&&!r);
    CHECK(!getservbyname_r("current",tcp,&s,b,sizeof b,&r)&&r==&s&&s.s_port==htons(45005));
    CHECK(getservbyname("current",tcp)==shared_name&&shared_name->s_port==htons(45005));
    CHECK(!getservbyport(htons(45001),tcp));
    CHECK(getservbyport(htons(45005),tcp)==shared_port&&!strcmp(shared_port->s_name,"first"));
    CHECK(!getservbyport_r(htons(45006),udp,&s,b,sizeof b,&r)&&r==&s&&!strcmp(s.s_name,"second"));
    const char moved[]="moved 45007/tcp current\n";
    file("/etc/services",moved,sizeof moved-1);
    CHECK(getservbyport_r(htons(45005),tcp,&s,b,sizeof b,&r)==ENOENT&&!r);
    CHECK(!getservbyport_r(htons(45007),tcp,&s,b,sizeof b,&r)&&r==&s&&!strcmp(s.s_name,"moved"));
    errno=EDOM;setservent(0);CHECK(errno==EDOM);
    CHECK(!getservent()&&errno==EDOM);
    CHECK(!getservbyname_r("current",tcp,&s,b,sizeof b,&r)&&r==&s&&s.s_port==htons(45007));
    CHECK(getservbyname("current",tcp)==shared_name&&shared_name->s_port==htons(45007));
}
static void protocols(void) {
    struct protoent *first,*p;char **aliases;
    static const struct {int number;const char *name;} expected[]={
        {0,"ip"},{1,"icmp"},{2,"igmp"},{3,"ggp"},{4,"ipencap"},{5,"st"},
        {6,"tcp"},{8,"egp"},{12,"pup"},{17,"udp"},{20,"hmp"},{22,"xns-idp"},
        {27,"rdp"},{29,"iso-tp4"},{36,"xtp"},{37,"ddp"},{38,"idpr-cmtp"},
        {41,"ipv6"},{43,"ipv6-route"},{44,"ipv6-frag"},{45,"idrp"},
        {46,"rsvp"},{47,"gre"},{50,"esp"},{51,"ah"},{57,"skip"},
        {58,"ipv6-icmp"},{59,"ipv6-nonxt"},{60,"ipv6-opts"},{73,"rspf"},
        {81,"vmtp"},{89,"ospf"},{94,"ipip"},{98,"encap"},{103,"pim"},
        {255,"raw"}
    };
    const char altered[]="invented 6 invented-alias\n";
    file("/etc/protocols",altered,sizeof altered-1);
    errno=EDOM;setprotoent(1);CHECK(errno==EDOM);
    first=getprotoent();CHECK(first&&first->p_proto==0&&!strcmp(first->p_name,"ip")&&errno==EDOM);
    aliases=first->p_aliases;CHECK(aliases&&!aliases[0]);
    p=getprotobyname("tcp");CHECK(p==first&&p->p_aliases==aliases&&p->p_proto==6&&!strcmp(p->p_name,"tcp")&&errno==EDOM);
    p=getprotoent();CHECK(p==first&&p->p_proto==8&&!strcmp(p->p_name,"egp")&&errno==EDOM);
    CHECK(!getprotobyname("TCP")&&errno==EDOM);
    CHECK(!getprotoent()&&errno==EDOM);
    p=getprotobynumber(255);CHECK(p==first&&p->p_proto==255&&!strcmp(p->p_name,"raw")&&errno==EDOM);
    CHECK(!getprotoent()&&errno==EDOM);
    endprotoent();CHECK(errno==EDOM);
    p=getprotoent();CHECK(p==first&&p->p_proto==0&&!strcmp(p->p_name,"ip")&&errno==EDOM);
    setprotoent(-7);CHECK(errno==EDOM);
    for(unsigned i=0;i<sizeof expected/sizeof expected[0];i++) {
        p=getprotoent();CHECK(p==first&&p->p_aliases==aliases&&!aliases[0]&&p->p_proto==expected[i].number&&!strcmp(p->p_name,expected[i].name)&&errno==EDOM);
    }
    CHECK(!getprotoent()&&errno==EDOM);
    CHECK(!getprotobyname("invented")&&errno==EDOM);
    CHECK(!getprotobynumber(256)&&errno==EDOM);
}
static void service_buffers(void) {
    struct servent s,*r;_Alignas(16) char raw[128];
    for(unsigned i=0;i<8;i++) {
        char *b=raw+i;size_t align=-(uintptr_t)b&7;memset(raw,0x5a,sizeof raw);
        CHECK(getservbyname_r("alt","bad",&s,b,16+align-1,&r)==ERANGE&&!r);
        CHECK(getservbyname_r("alt","bad",&s,b,16+align,&r)==EINVAL&&!r);
        CHECK(!getservbyname_r("alt","tcp",&s,b,16+align,&r)&&r==&s&&s.s_aliases==(void*)(b+align));
        CHECK(getservbyport_r(htons(45001),"bad",&s,b,16+align,&r)==ERANGE&&!r);
        CHECK(getservbyport_r(htons(45001),"bad",&s,b,17+align,&r)==EINVAL&&!r);
        CHECK(getservbyport_r(htons(45001),"tcp",&s,b,16+align+strlen("tcp-second"),&r)==ERANGE&&!r);
        CHECK(!getservbyport_r(htons(45001),"tcp",&s,b,17+align+strlen("tcp-second"),&r)&&r==&s);
    }
    const char *numeric[]={"","80"," +80","-0","99999999999999999999999999999999"};
    for(unsigned i=0;i<5;i++)CHECK(getservbyname_r(numeric[i],"bad",&s,raw,0,&r)==ENOENT&&!r);
    CHECK(getservbyname_r("absent","tcp",&s,raw,sizeof raw,&r)==ENOENT&&!r);
    CHECK(getservbyport_r(htons(49999),"tcp",&s,raw,sizeof raw,&r)==ENOENT&&!r);
}
static void deny(int number,int error) {
    struct instruction { unsigned short code;unsigned char yes,no;unsigned value; };
    struct program {unsigned short count;struct instruction *instructions;};
    struct instruction ins[]={{0x20,0,0,0},{0x15,0,1,(unsigned)number},{0x06,0,0,0x00050000|(unsigned)error},{0x06,0,0,0x7fff0000}};
    struct program p={4,ins};CHECK(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)==0&&syscall(SYS_seccomp,1,0,&p)==0);
}
static void fcntl_error(void) {
    struct servent s,*r;char b[128];
    deny(SYS_fcntl,EACCES);
    errno=EDOM;
    CHECK(getservbyname_r("alt","tcp",&s,b,sizeof b,&r)==0&&r==&s&&errno==EINVAL);
}
static void io_errors(const char *scenario) {
    struct hostent h,*hr;struct servent s,*sr;char b[1024];int error=97;
    int code=!strcmp(scenario,"open-errors")?EIO:EACCES;
    if(!strcmp(scenario,"read-errors"))deny(SYS_read,EIO);
    else {deny(SYS_open,code);deny(SYS_openat,code);}
    if(!strcmp(scenario,"open-errors")) {
        errno=EDOM;CHECK(gethostbyname_r("alias.test",&h,b,sizeof b,&hr,&error)==EIO&&!hr&&error==NO_RECOVERY&&errno==EIO);
        CHECK(getservbyname_r("alt","tcp",&s,b,sizeof b,&sr)==ENOMEM&&!sr&&errno==EIO);
    } else if(!strcmp(scenario,"read-errors")) {
        CHECK(getservbyname_r("alt","tcp",&s,b,sizeof b,&sr)==ENOENT&&!sr&&errno==EIO);
    } else CHECK(getservbyname_r("alt","tcp",&s,b,sizeof b,&sr)==ENOENT&&!sr&&errno==EACCES);
}
static void socket_error(void) {
    struct hostent h,*r;char b[1024];int error=97;deny(SYS_socket,EACCES);errno=EDOM;h_errno=96;
    CHECK(gethostbyname_r("a.example.test",&h,b,sizeof b,&r,&error)==EACCES&&!r&&error==NO_RECOVERY&&errno==EACCES&&h_errno==96);
    CHECK(!gethostbyname_r("127.1",&h,b,sizeof b,&r,&error)&&r==&h);
    unsigned char ip[]={192,0,2,99};error=97;
    CHECK(!gethostbyaddr_r(ip,4,AF_INET,&h,b,sizeof b,&r,&error)&&r==&h&&error==97&&!strcmp(h.h_name,"192.0.2.99"));
    unsigned char answer[512];h_errno=96;
    CHECK(res_query("a.example.test",C_IN,T_A,answer,sizeof answer)==-1&&h_errno==TRY_AGAIN);
}
static void empty_and_reporting(void) {
    errno=EDOM;h_errno=96;
    CHECK(!gethostent()&&!getnetent()&&!getnetbyname((void*)1)&&!getnetbyaddr(0xffffffff,AF_INET)&&errno==EDOM&&h_errno==96);
    int pipefd[2],saved=dup(2);CHECK(saved>=0&&!pipe(pipefd)&&dup2(pipefd[1],2)==2&&!close(pipefd[1]));
    h_errno=HOST_NOT_FOUND;herror("prefix");h_errno=TRY_AGAIN;herror(0);h_errno=NO_DATA;herror("");
    CHECK(!fflush(stderr)&&dup2(saved,2)==2&&!close(saved));char b[256];ssize_t count=read(pipefd[0],b,sizeof b);CHECK(count>0&&!close(pipefd[0]));
    const char expected[]="prefix: Host not found\nTry again\n: Address not available\n";CHECK(count==(ssize_t)sizeof expected-1&&!memcmp(b,expected,sizeof expected-1));
}
static void *zero_timeout_worker(void *argument) {
    int marker=(int)(uintptr_t)argument;
    for(unsigned i=0;i<16;i++) {
        struct addrinfo retained={0},hint={0},*result=&retained;
        hint.ai_family=i%2?AF_INET:AF_UNSPEC;
        hint.ai_socktype=SOCK_STREAM;
        errno=EDOM;h_errno=marker;
        CHECK(getaddrinfo("zero-timeout.example.test","80",&hint,&result)==EAI_AGAIN);
        CHECK(result==&retained && h_errno==marker);
        int state;
        CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&state));
        CHECK(state==PTHREAD_CANCEL_ENABLE);
        CHECK(!pthread_setcancelstate(state,0));
    }
    return 0;
}
static void zero_timeout(void) {
    /* A zero elapsed budget still acquires and retires the source socket,
     * without sending a request or publishing an allocated result. */
    const char conf[]="nameserver 127.0.0.1\noptions timeout:0 attempts:1\n";
    file("/etc/resolv.conf",conf,sizeof conf-1);
    int first=socket(AF_INET,SOCK_DGRAM,0);CHECK(first>=0&&!close(first));
    zero_timeout_worker((void*)73);
    pthread_t a,b;
    CHECK(!pthread_create(&a,0,zero_timeout_worker,(void*)74));
    CHECK(!pthread_create(&b,0,zero_timeout_worker,(void*)75));
    CHECK(!pthread_join(a,0)&&!pthread_join(b,0)&&h_errno==73);
    int after=socket(AF_INET,SOCK_DGRAM,0);CHECK(after==first&&!close(after));
    setup();
}
static void addrinfo(void) {
    struct addrinfo hint={0},*r=(void*)1;
    hint.ai_family=AF_INET;CHECK(getaddrinfo("alias.test","alt",&hint,&r)==0&&r);
    unsigned n=0;char *canon=r->ai_canonname;CHECK(canon&&!strcmp(canon,"canonical.test"));
    for(struct addrinfo *p=r;p;p=p->ai_next) {CHECK(p->ai_flags==0&&p->ai_canonname==canon&&p->ai_family==AF_INET&&((struct sockaddr_in*)p->ai_addr)->sin_port==htons(45001));n++;}CHECK(n==4);freeaddrinfo(r);
    hint.ai_flags=AI_NUMERICSERV;r=(void*)1;CHECK(getaddrinfo("","alt",&hint,&r)==EAI_NONAME&&r==(void*)1);
    hint.ai_flags=0;hint.ai_family=AF_UNSPEC;hint.ai_socktype=SOCK_STREAM;CHECK(!getaddrinfo(0,"80",&hint,&r));n=0;for(struct addrinfo*p=r;p;p=p->ai_next)n++;CHECK(n==2);freeaddrinfo(r);
    hint.ai_family=AF_INET6;hint.ai_flags=AI_V4MAPPED;CHECK(!getaddrinfo("alias.test","80",&hint,&r));CHECK(r->ai_family==AF_INET6&&!r->ai_next);freeaddrinfo(r);
    hint.ai_flags=AI_ADDRCONFIG;hint.ai_family=AF_INET;CHECK(!getaddrinfo("127.1","80",&hint,&r));freeaddrinfo(r);
    struct sockaddr_in sa={.sin_family=AF_INET,.sin_port=htons(45001)};char service[32];CHECK(!getnameinfo((void*)&sa,sizeof sa,0,0,service,sizeof service,0)&&!strcmp(service,"tcp-second"));
    zero_timeout();
}
static void *thread_lookup(void *arg) {
    int marker=(int)(uintptr_t)arg;h_errno=marker;struct hostent h,*hr;struct servent s,*sr;char b[2048],sb[64];
    for(unsigned i=0;i<30;i++) {int error=97;CHECK(!gethostbyname_r("alias.test",&h,b,sizeof b,&hr,&error)&&hr==&h&&error==97&&h_errno==marker);CHECK(!getservbyname_r("alt","tcp",&s,sb,sizeof sb,&sr)&&sr==&s&&h_errno==marker);contained(&h,b,sizeof b);}
    return 0;
}
static void threads_and_fork(void) {
    pthread_t a,b;h_errno=95;CHECK(!pthread_create(&a,0,thread_lookup,(void*)71)&&!pthread_create(&b,0,thread_lookup,(void*)72));CHECK(!pthread_join(a,0)&&!pthread_join(b,0)&&h_errno==95);
    struct hostent *forward=gethostbyname("alias.test");CHECK(forward&&!strcmp(forward->h_name,"canonical.test"));unsigned char ip[]={198,51,100,42};
    struct hostent *reverse=gethostbyaddr(ip,4,AF_INET);CHECK(reverse&&reverse!=forward&&!strcmp(forward->h_name,"canonical.test"));
    pid_t child=fork();CHECK(child>=0);if(!child){CHECK(gethostbyname("127.1"));CHECK(!strcmp(reverse->h_name,"reverse.example.test"));_exit(0);}
    int status;CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));CHECK(!strcmp(forward->h_name,"canonical.test"));
}
static void allocation_failure(void) {
    struct rlimit limit;CHECK(!getrlimit(RLIMIT_AS,&limit));limit.rlim_cur=64*1024*1024;CHECK(!setrlimit(RLIMIT_AS,&limit));
    while(malloc(127));CHECK(errno==ENOMEM);h_errno=96;CHECK(!gethostbyname("127.1")&&h_errno==NO_RECOVERY&&errno==ENOMEM);
    struct hostent h,*r;char b[256];int error=97;CHECK(!gethostbyname_r("127.1",&h,b,sizeof b,&r,&error)&&r==&h&&error==97);address(&h,0,AF_INET,"127.0.0.1");
}
int main(int argc,char **argv) {
    CHECK(argc==2);setup();const char *s=argv[1];
    if(!strcmp(s,"query-domain")){query_domain_construction();query_domain_answers();}else if(!strcmp(s,"host-numeric"))host_numeric();else if(!strcmp(s,"host-local"))host_local();else if(!strcmp(s,"host-buffers"))host_buffers();else if(!strcmp(s,"host-many"))host_many();else if(!strcmp(s,"host-dns"))host_dns();else if(!strcmp(s,"dns-record-order"))dns_record_order();else if(!strcmp(s,"dns-record-prefix"))dns_record_prefix();else if(!strcmp(s,"dns-batch"))dns_batch();else if(!strcmp(s,"search-precedence"))search_precedence();
    else if(!strcmp(s,"mixed-family"))mixed_family_precedence();else if(!strcmp(s,"reverse-local"))reverse_local();else if(!strcmp(s,"reverse-dns"))reverse_dns();else if(!strcmp(s,"services")){services();protocols();}else if(!strcmp(s,"service-buffers"))service_buffers();else if(!strcmp(s,"empty-reporting"))empty_and_reporting();else if(!strcmp(s,"addrinfo"))addrinfo();else if(!strcmp(s,"threads-fork"))threads_and_fork();else if(!strcmp(s,"allocation"))allocation_failure();else if(!strcmp(s,"socket-error"))socket_error();else if(!strcmp(s,"fcntl-error"))fcntl_error();else io_errors(s);
    puts("classic netdb scenario passed");return 0;
}
